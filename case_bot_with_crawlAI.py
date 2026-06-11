import asyncio
from crawl4ai import *

async def main():
    async with AsyncWebCrawler() as crawler:
        result = await crawler.arun(
            url="https://iapps.courts.state.ny.us/nyscef/CaseSearch",
            config=CrawlerRunConfig(
                js_code="""
                    // Wait for the page to load
                    await new Promise(r => setTimeout(r, 2000));

                    // Find the search input and type the search term
                    const searchInput = document.querySelector('input[type="text"]');
                    if (searchInput) {
                        searchInput.value = 'apple.co';
                        searchInput.dispatchEvent(new Event('input', { bubbles: true }));
                        searchInput.dispatchEvent(new Event('change', { bubbles: true }));
                    }

                    // Find and click the search button
                    const searchButton = document.querySelector('input[type="submit"], button[type="submit"], button');
                    if (searchButton) {
                        searchButton.click();
                    }

                    // Wait for results to load
                    await new Promise(r => setTimeout(r, 3000));
                """,
                wait_for="body",
                page_timeout=30000,
            )
        )
        print(result.markdown)

if __name__ == "__main__":
    asyncio.run(main())