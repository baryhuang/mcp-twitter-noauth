import logging
from typing import Any, Dict, List, Optional
import os
from dotenv import load_dotenv
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from pydantic import AnyUrl
import json
from datetime import datetime, timedelta
from dateutil.tz import tzlocal
import argparse
import requests
import base64
import hashlib
import secrets

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('mcp_server_twitter_noauth')
logger.setLevel(logging.DEBUG)

def convert_datetime_fields(obj: Any) -> Any:
    """Convert any datetime or tzlocal objects to string in the given object"""
    if isinstance(obj, dict):
        return {k: convert_datetime_fields(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetime_fields(item) for item in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, tzlocal):
        # Get the current timezone offset
        offset = datetime.now(tzlocal()).strftime('%z')
        return f"UTC{offset[:3]}:{offset[3:]}"  # Format like "UTC+08:00" or "UTC-05:00"
    return obj

class TwitterClient:
    def __init__(self, access_token: Optional[str] = None, refresh_token: Optional[str] = None, 
                 client_id: Optional[str] = None, client_secret: Optional[str] = None):
        if not access_token and not refresh_token:
            raise ValueError("Either access_token or refresh_token must be provided")
        
        self.api_base_url = "https://api.twitter.com/2"
        self.oauth_url = "https://api.x.com/2/oauth2/token"
        
        # Store tokens and client credentials
        self.access_token = access_token
        self._refresh_token = refresh_token  # Renamed to avoid conflict with the method
        self.client_id = client_id
        self.client_secret = client_secret
        
        # Generate code verifier and challenge for PKCE if not provided
        self.code_verifier = secrets.token_urlsafe(64)[:128]  # Twitter documentation specifies up to 128 chars
        self.code_challenge = self._generate_code_challenge(self.code_verifier)

    def _generate_code_challenge(self, verifier: str) -> str:
        """Generate a code challenge from a code verifier for PKCE
        
        Args:
            verifier: The code verifier
            
        Returns:
            Code challenge string
        """
        hashed = hashlib.sha256(verifier.encode()).digest()
        encoded = base64.urlsafe_b64encode(hashed).decode().rstrip('=')
        return encoded

    def get_user_id_by_username(self, username: str) -> str:
        """Lookup a user ID by username
        
        Args:
            username: Twitter username/handle (without the @ symbol)
            
        Returns:
            JSON string with user data including the user ID
        """
        try:
            if not self.access_token:
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
            
            # Remove @ symbol if it's included
            if username.startswith('@'):
                username = username[1:]
                
            logger.debug(f"Looking up user ID for username: {username}")
            
            # Twitter API v2 user lookup by username endpoint
            url = f"{self.api_base_url}/users/by/username/{username}"
            
            headers = {
                "Authorization": f"Bearer {self.access_token}"
            }
            
            params = {
                "user.fields": "id,name,username"
            }
            
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            result = response.json()
            
            # Extract the user ID from the response
            if "data" in result and "id" in result["data"]:
                user_id = result["data"]["id"]
                logger.debug(f"Found user ID: {user_id} for username: {username}")
                return json.dumps({
                    "user_id": user_id,
                    "data": result["data"],
                    "status": "success"
                })
            else:
                return json.dumps({
                    "error": "User not found or ID not available",
                    "status": "error"
                })
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})
        except Exception as e:
            logger.error(f"Exception in get_user_id_by_username: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})

    def refresh_token(self, client_id: str, client_secret: str = None) -> str:
        """Refresh the access token using the refresh token
        
        Args:
            client_id: Twitter OAuth2 client ID
            client_secret: Twitter OAuth2 client secret (only required for confidential clients)
        """
        if not self._refresh_token:  # Changed to use the renamed attribute
            return json.dumps({
                "error": "No refresh token provided",
                "status": "error"
            })
            
        try:
            # Set up the request to refresh the token
            url = self.oauth_url
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            # For confidential clients, add Authorization header
            if client_id and client_secret:
                # Create basic auth header for confidential clients
                auth_string = f"{client_id}:{client_secret}"
                encoded_auth = base64.b64encode(auth_string.encode()).decode()
                headers["Authorization"] = f"Basic {encoded_auth}"
            
            # Prepare request data based on Twitter's OAuth2 implementation
            data = {
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,  # Changed to use the renamed attribute
            }
            
            # Client ID is required in the body for public clients
            if not client_secret:
                data["client_id"] = client_id
            
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            logger.debug(f"Token refresh response: {token_data}")
            
            # Update access token for API calls
            self.access_token = token_data.get("access_token")
            
            # Update refresh token if a new one is provided
            new_refresh_token = token_data.get("refresh_token")
            if new_refresh_token:
                self._refresh_token = new_refresh_token  # Changed to use the renamed attribute
            
            # Calculate expiration time if provided
            expires_in = token_data.get("expires_in")
            expires_at = None
            
            if expires_in:
                expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            # Return the new access token and its expiration
            return json.dumps({
                "access_token": self.access_token,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "expires_in": expires_in,
                "refresh_token": token_data.get("refresh_token", self._refresh_token),  # Changed to use the renamed attribute
                "scope": token_data.get("scope", ""),
                "status": "success"
            })
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Token refresh error: {str(e)}")
            return json.dumps({
                "error": "Token refresh failed. Please provide valid client ID and client secret.",
                "details": str(e),
                "status": "error"
            })
        except Exception as e:
            logger.error(f"Exception: {str(e)}")
            return json.dumps({
                "error": str(e),
                "status": "error"
            })

    def search_tweets(self, query: str, max_results: int = 10) -> str:
        """Search for tweets using the Twitter API
        
        Args:
            query: The search query to execute
            max_results: Maximum number of tweets to return (default: 10)
            
        Returns:
            JSON string with search results
        """
        try:
            if not self.access_token:
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
            
            logger.debug(f"Searching tweets with query: {query}, max_results: {max_results}")
            
            # Twitter API v2 search recent endpoint
            url = f"{self.api_base_url}/tweets/search/recent"
            
            headers = {
                "Authorization": f"Bearer {self.access_token}"
            }
            
            params = {
                "query": query,
                "max_results": max_results,
                "tweet.fields": "id,text,created_at,author_id",
                "expansions": "author_id",
                "user.fields": "id,name,username"
            }
            
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            # Return the raw JSON response
            return json.dumps(response.json())
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})
        except Exception as e:
            logger.error(f"Exception in search_tweets: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})

    def get_user_tweets(self, user_id: str = None, username: str = None, max_results: int = 10) -> str:
        """Get recent tweets by a specific user
        
        Args:
            user_id: Twitter user ID
            username: Twitter username/handle (without @ symbol)
            max_results: Maximum number of tweets to return (default: 10)
            
        Returns:
            JSON string with user tweets
        """
        try:
            if not self.access_token:
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
            
            # If username is provided but not user_id, look up the user_id
            if not user_id and username:
                # Remove @ symbol if it's included
                if username.startswith('@'):
                    username = username[1:]
                
                logger.debug(f"Looking up user ID for username: {username}")
                user_lookup_result = self.get_user_id_by_username(username)
                user_lookup_data = json.loads(user_lookup_result)
                
                if user_lookup_data.get("status") == "success":
                    user_id = user_lookup_data.get("user_id")
                    logger.debug(f"Found user ID: {user_id}")
                else:
                    return json.dumps({
                        "error": f"Could not find user ID for username: {username}",
                        "details": user_lookup_data.get("error", "No details available"),
                        "status": "error"
                    })
            
            if not user_id:
                return json.dumps({
                    "error": "Either user_id or username is required",
                    "status": "error"
                })
            
            logger.debug(f"Getting tweets for user ID: {user_id}, max_results: {max_results}")
            
            # Twitter API v2 user tweets endpoint
            url = f"{self.api_base_url}/users/{user_id}/tweets"
            
            headers = {
                "Authorization": f"Bearer {self.access_token}"
            }
            
            params = {
                "max_results": max_results,
                "tweet.fields": "id,text,created_at,conversation_id",
                "expansions": "author_id",
                "user.fields": "id,name,username"
            }
            
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            # Return the raw JSON response
            return json.dumps(response.json())
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})
        except Exception as e:
            logger.error(f"Exception in get_user_tweets: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})

    def get_user_replies(self, user_id: str = None, username: str = None, max_results: int = 10) -> str:
        """Get recent replies by a specific user
        
        Args:
            user_id: Twitter user ID
            username: Twitter username/handle (without @ symbol)
            max_results: Maximum number of tweets to return (default: 10)
            
        Returns:
            JSON string with user replies
        """
        try:
            if not self.access_token:
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
            
            # If username is provided but not user_id, look up the user_id
            if not user_id and username:
                # Remove @ symbol if it's included
                if username.startswith('@'):
                    username = username[1:]
                    
                logger.debug(f"Looking up user ID for username: {username}")
                user_lookup_result = self.get_user_id_by_username(username)
                user_lookup_data = json.loads(user_lookup_result)
                
                if user_lookup_data.get("status") == "success":
                    user_id = user_lookup_data.get("user_id")
                    logger.debug(f"Found user ID: {user_id}")
                else:
                    return json.dumps({
                        "error": f"Could not find user ID for username: {username}",
                        "details": user_lookup_data.get("error", "No details available"),
                        "status": "error"
                    })
            
            if not user_id:
                return json.dumps({
                    "error": "Either user_id or username is required",
                    "status": "error"
                })
            
            logger.debug(f"Getting replies for user ID: {user_id}, max_results: {max_results}")
            
            # We'll use the search endpoint with a specific query to find replies
            url = f"{self.api_base_url}/tweets/search/recent"
            
            headers = {
                "Authorization": f"Bearer {self.access_token}"
            }
            
            # Query for tweets that are replies from the specified user
            query = f"from:{user_id} is:reply"
            
            params = {
                "query": query,
                "max_results": max_results,
                "tweet.fields": "id,text,created_at,in_reply_to_user_id,conversation_id",
                "expansions": "author_id,in_reply_to_user_id,referenced_tweets.id",
                "user.fields": "id,name,username"
            }
            
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            # Return the raw JSON response
            return json.dumps(response.json())
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})
        except Exception as e:
            logger.error(f"Exception in get_user_replies: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})

    def post_tweet(self, text: str) -> str:
        """Post a new tweet
        
        Args:
            text: The tweet text content
        """
        try:
            if not self.access_token:
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
            
            logger.debug(f"Posting tweet with text: {text[:30]}...")
            
            # Twitter API v2 create tweet endpoint
            url = f"{self.api_base_url}/tweets"
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            # Create request body
            data = {
                "text": text
            }
            
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            
            # Return the raw JSON response
            return json.dumps(response.json())
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})
        except Exception as e:
            logger.error(f"Exception in post_tweet: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})

    def reply_to_tweet(self, tweet_id: str, text: str) -> str:
        """Reply to an existing tweet
        
        Args:
            tweet_id: ID of the tweet to reply to
            text: The reply text content
        """
        try:
            if not self.access_token:
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
            
            logger.debug(f"Replying to tweet {tweet_id} with text: {text[:30]}...")
            
            # Twitter API v2 create tweet (reply) endpoint
            url = f"{self.api_base_url}/tweets"
            
            headers = {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
            
            # Create request body with reply information
            data = {
                "text": text,
                "reply": {
                    "in_reply_to_tweet_id": tweet_id
                }
            }
            
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            
            # Return the raw JSON response
            return json.dumps(response.json())
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request error: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})
        except Exception as e:
            logger.error(f"Exception in reply_to_tweet: {str(e)}")
            return json.dumps({"error": str(e), "status": "error"})

async def main():
    """Run the Twitter MCP server."""
    logger.info("Twitter server starting")
    server = Server("twitter-client")

    @server.list_resources()
    async def handle_list_resources() -> list[types.Resource]:
        return []

    @server.read_resource()
    async def handle_read_resource(uri: AnyUrl) -> str:
        if uri.scheme != "twitter":
            raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

        path = str(uri).replace("twitter://", "")
        return ""

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        """List available tools"""
        return [
            types.Tool(
                name="twitter_refresh_token",
                description="Refresh the access token using the refresh token and client credentials",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "twitter_access_token": {"type": "string", "description": "Twitter OAuth2 access token (optional if expired)"},
                        "twitter_refresh_token": {"type": "string", "description": "Twitter OAuth2 refresh token"},
                        "twitter_client_id": {"type": "string", "description": "Twitter OAuth2 client ID for token refresh"},
                        "twitter_client_secret": {"type": "string", "description": "Twitter OAuth2 client secret (required only for confidential clients)"}
                    },
                    "required": ["twitter_refresh_token", "twitter_client_id"]
                },
            ),
            types.Tool(
                name="twitter_search_tweets",
                description="Search for tweets using the Twitter API",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "twitter_access_token": {"type": "string", "description": "Twitter OAuth2 access token"},
                        "query": {"type": "string", "description": "The search query to execute"},
                        "max_results": {"type": "integer", "description": "Maximum number of tweets to return (default: 10)"}
                    },
                    "required": ["twitter_access_token", "query"]
                },
            ),
            types.Tool(
                name="twitter_get_user_tweets",
                description="Get recent tweets by a specific user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "twitter_access_token": {"type": "string", "description": "Twitter OAuth2 access token"},
                        "user_id": {"type": "string", "description": "Twitter user ID (optional if username is provided)"},
                        "username": {"type": "string", "description": "Twitter username/handle (optional if user_id is provided)"},
                        "max_results": {"type": "integer", "description": "Maximum number of tweets to return (default: 10)"}
                    },
                    "required": ["twitter_access_token"]
                },
            ),
            types.Tool(
                name="twitter_get_user_replies",
                description="Get recent replies by a specific user",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "twitter_access_token": {"type": "string", "description": "Twitter OAuth2 access token"},
                        "user_id": {"type": "string", "description": "Twitter user ID (optional if username is provided)"},
                        "username": {"type": "string", "description": "Twitter username/handle (optional if user_id is provided)"},
                        "max_results": {"type": "integer", "description": "Maximum number of tweets to return (default: 10)"}
                    },
                    "required": ["twitter_access_token"]
                },
            ),
            types.Tool(
                name="twitter_post_tweet",
                description="Post a new tweet",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "twitter_access_token": {"type": "string", "description": "Twitter OAuth2 access token"},
                        "text": {"type": "string", "description": "The tweet text content"}
                    },
                    "required": ["twitter_access_token", "text"]
                },
            ),
            types.Tool(
                name="twitter_reply_to_tweet",
                description="Reply to an existing tweet",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "twitter_access_token": {"type": "string", "description": "Twitter OAuth2 access token"},
                        "tweet_id": {"type": "string", "description": "ID of the tweet to reply to"},
                        "text": {"type": "string", "description": "The reply text content"}
                    },
                    "required": ["twitter_access_token", "tweet_id", "text"]
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Handle tool execution requests"""
        try:
            if not arguments:
                raise ValueError(f"Missing arguments for {name}")
            
            if name == "twitter_refresh_token":
                # For refresh token, we need refresh token, client ID and secret
                refresh_token = arguments.get("twitter_refresh_token")
                client_id = arguments.get("twitter_client_id")
                client_secret = arguments.get("twitter_client_secret")  # Optional for public clients
                access_token = arguments.get("twitter_access_token")  # Optional for refresh
                
                if not refresh_token:
                    raise ValueError("twitter_refresh_token is required for token refresh")
                
                if not client_id:
                    raise ValueError("twitter_client_id is required for token refresh")
                
                # Initialize Twitter client for token refresh
                twitter = TwitterClient(
                    access_token=access_token, 
                    refresh_token=refresh_token,
                    client_id=client_id,
                    client_secret=client_secret
                )
                
                # Call the refresh_token method
                results = twitter.refresh_token(client_id=client_id, client_secret=client_secret)
                return [types.TextContent(type="text", text=results)]
            
            else:
                # For all other tools, we need access token
                access_token = arguments.get("twitter_access_token")
                
                if not access_token:
                    raise ValueError("twitter_access_token is required")
                
                # Initialize Twitter client with access token
                twitter = TwitterClient(access_token=access_token)
                
                if name == "twitter_search_tweets":
                    query = arguments.get("query")
                    max_results = int(arguments.get("max_results", 10))
                    
                    if not query:
                        raise ValueError("query is required for twitter_search_tweets")
                    
                    results = twitter.search_tweets(query=query, max_results=max_results)
                    return [types.TextContent(type="text", text=results)]
                
                elif name == "twitter_get_user_tweets":
                    user_id = arguments.get("user_id")
                    username = arguments.get("username")
                    max_results = int(arguments.get("max_results", 10))
                    
                    if not user_id and not username:
                        raise ValueError("Either user_id or username is required for twitter_get_user_tweets")
                    
                    results = twitter.get_user_tweets(user_id=user_id, username=username, max_results=max_results)
                    return [types.TextContent(type="text", text=results)]
                
                elif name == "twitter_get_user_replies":
                    user_id = arguments.get("user_id")
                    username = arguments.get("username")
                    max_results = int(arguments.get("max_results", 10))
                    
                    if not user_id and not username:
                        raise ValueError("Either user_id or username is required for twitter_get_user_replies")
                    
                    results = twitter.get_user_replies(user_id=user_id, username=username, max_results=max_results)
                    return [types.TextContent(type="text", text=results)]
                
                elif name == "twitter_post_tweet":
                    text = arguments.get("text")
                    
                    if not text:
                        raise ValueError("text is required for twitter_post_tweet")
                    
                    results = twitter.post_tweet(text=text)
                    return [types.TextContent(type="text", text=results)]
                
                elif name == "twitter_reply_to_tweet":
                    tweet_id = arguments.get("tweet_id")
                    text = arguments.get("text")
                    
                    if not tweet_id:
                        raise ValueError("tweet_id is required for twitter_reply_to_tweet")
                    
                    if not text:
                        raise ValueError("text is required for twitter_reply_to_tweet")
                    
                    results = twitter.reply_to_tweet(tweet_id=tweet_id, text=text)
                    return [types.TextContent(type="text", text=results)]
                
                else:
                    raise ValueError(f"Unknown tool: {name}")

        except Exception as e:
            logger.error(f"Error in handle_call_tool for {name}: {str(e)}", exc_info=True)
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        logger.info("Server running with stdio transport")
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="twitter",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    import asyncio
    
    # Simplified command-line with no OAuth parameters
    asyncio.run(main()) 