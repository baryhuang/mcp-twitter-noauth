# MCP Server - Twitter NoAuth 

A MCP (Model Context Protocol) server that provides Twitter API access without local credential or token setup. Provides core Twitter operations like searching tweets, getting user tweets, posting tweets, and replying to tweets.

## Why MCP Twitter NoAuth Server?
### Critical Advantages
- **Headless & Remote Operation**: This server can run completely headless in remote environments with no browser and no local file access.
- **Decoupled Architecture**: Any client can complete the OAuth flow independently, then pass credentials as context to this MCP server, creating a complete separation between credential storage and server implementation.

### Nice but not critical
- **Focused Functionality**: Provides core Twitter operations like searching tweets, getting user tweets, posting tweets, and replying to tweets.
- **Docker-Ready**: Designed with containerization in mind for a well-isolated, environment-independent, one-click setup.
- **Reliable Dependencies**: Built on standard Python requests library for Twitter API integration.

## Features

- Search tweets using Twitter API
- Get recent tweets by a specific user
- Get recent replies by a specific user
- Post new tweets
- Reply to existing tweets
- Refresh access tokens separately
- Automatic refresh token handling

## Prerequisites

- Python 3.10 or higher
- Twitter API credentials (client ID, client secret, access token, and refresh token)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-twitter-noauth.git
cd mcp-twitter-noauth

# Install dependencies
pip install -e .
```

## Docker

### Building the Docker Image

```bash
# Build the Docker image
docker build -t mcp-twitter-noauth .
```

## Usage with Claude Desktop

### Docker Usage

You can configure Claude Desktop to use the Docker image by adding the following to your Claude configuration:

```json
{
  "mcpServers": {
    "twitter": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "buryhuang/mcp-twitter-noauth:latest"
      ]
    }
  }
}
```

Note: With this configuration, you'll need to provide your Twitter API credentials in the tool calls as shown in the [Using the Tools](#using-the-tools) section. Twitter credentials are not passed as environment variables to maintain separation between credential storage and server implementation.

## Cross-Platform Publishing

To publish the Docker image for multiple platforms, you can use the `docker buildx` command. Follow these steps:

1. **Create a new builder instance** (if you haven't already):
   ```bash
   docker buildx create --use
   ```

2. **Build and push the image for multiple platforms**:
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t buryhuang/mcp-twitter-noauth:latest --push .
   ```

3. **Verify the image is available for the specified platforms**:
   ```bash
   docker buildx imagetools inspect buryhuang/mcp-twitter-noauth:latest
   ```

## Usage

The server provides Twitter functionality through MCP tools. Authentication handling is simplified with a dedicated token refresh tool.

### Starting the Server

```bash
mcp-server-twitter-noauth
```

### Using the Tools

When using an MCP client like Claude, you have two main ways to handle authentication:

#### Refreshing Tokens (First Step or When Tokens Expire)

If you have both access and refresh tokens:
```json
{
  "twitter_access_token": "your_access_token",
  "twitter_refresh_token": "your_refresh_token",
  "twitter_client_id": "your_client_id",
  "twitter_client_secret": "your_client_secret"
}
```

If your access token has expired, you can refresh with just the refresh token:
```json
{
  "twitter_refresh_token": "your_refresh_token",
  "twitter_client_id": "your_client_id",
  "twitter_client_secret": "your_client_secret"
}
```

This will return a new access token and its expiration time, which you can use for subsequent calls.

#### Searching Tweets

Search for tweets using the Twitter API:

```json
{
  "twitter_access_token": "your_access_token",
  "query": "your search query",
  "max_results": 10
}
```

Response includes tweet data including text, creation time, and author information.

#### Getting User Tweets

Get recent tweets by a specific user:

```json
{
  "twitter_access_token": "your_access_token",
  "user_id": "twitter_user_id",
  "max_results": 10
}
```

#### Getting User Replies

Get recent replies by a specific user:

```json
{
  "twitter_access_token": "your_access_token",
  "user_id": "twitter_user_id",
  "max_results": 10
}
```

#### Posting a Tweet

Post a new tweet:

```json
{
  "twitter_access_token": "your_access_token",
  "text": "This is a test tweet from the MCP Twitter server"
}
```

#### Replying to a Tweet

Reply to an existing tweet:

```json
{
  "twitter_access_token": "your_access_token",
  "tweet_id": "id_of_tweet_to_reply_to",
  "text": "This is a reply to the original tweet"
}
```

### Token Refresh Workflow

1. Start by calling the `twitter_refresh_token` tool with either:
   - Your full credentials (access token, refresh token, client ID, and client secret), or
   - Just your refresh token, client ID, and client secret if the access token has expired
2. Use the returned new access token for subsequent API calls.
3. If you get a response indicating token expiration, call the `twitter_refresh_token` tool again to get a new token.

This approach simplifies most API calls by not requiring client credentials for every operation, while still enabling token refresh when needed.

## Obtaining Twitter API Credentials

To obtain the required Twitter API credentials, follow these steps:

1. Go to the [Twitter Developer Portal](https://developer.twitter.com/en/portal/dashboard)
2. Create a new project and app
3. Set up OAuth 2.0 authentication
4. Configure the OAuth settings for your app
5. Generate client ID and client secret
6. Complete the OAuth flow to obtain access and refresh tokens

## Token Refreshing

This server implements automatic token refreshing. When your access token expires, the server will use the refresh token, client ID, and client secret to obtain a new access token without requiring user intervention.

## Security Note

This server requires direct access to your Twitter API credentials. Always keep your tokens and credentials secure and never share them with untrusted parties.

## License

See the LICENSE file for details. 
