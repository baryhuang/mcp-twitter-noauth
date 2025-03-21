import argparse
import asyncio
import logging
from . import server

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('mcp_twitter_noauth')

def main():
    logger.debug("Starting mcp-server-twitter-noauth main()")
    parser = argparse.ArgumentParser(description='Twitter NoAuth MCP Server')
    args = parser.parse_args()
    
    # Run the async main function
    logger.debug("About to run server.main()")
    asyncio.run(server.main())
    logger.debug("Server main() completed")

if __name__ == "__main__":
    main()

# Expose important items at package level
__all__ = ["main", "server"] 