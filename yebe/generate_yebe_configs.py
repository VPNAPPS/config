import requests
import pycountry
import re
import os
import sys
from dotenv import load_dotenv
from typing import Dict, List
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from create_configs_json import build_config
import json

# Load environment variables from .env file
load_dotenv()

class CountryDataFetcher:
    def __init__(self):
        self.base_url = os.getenv("BASE_URL")
        self.github_api_url = os.getenv("GGITHUB_API_URL")
        self.flag_offset = 127397


    def get_flag_emoji(self, country_code: str) -> str:
        """Convert ISO 3166-1 alpha-2 country code to flag emoji"""
        try:
            return ''.join(chr(self.flag_offset + ord(char)) for char in country_code.upper())
        except:
            return "⚡️"

    def get_country_name(self, country_code: str) -> str:
        """Get country name from country code using pycountry"""
        try:
            country = pycountry.countries.get(alpha_2=country_code.upper())
            return country.name if country else f"Fastest Location"
        except:
            return f"Fastest Location"

    def fetch_available_country_codes(self) -> List[str]:
        """Fetch all available country codes from the GitHub repository"""
        try:
            print("🔍 Fetching available country codes from GitHub...")
            response = requests.get(self.github_api_url, timeout=10)

            if response.status_code == 200:
                files = response.json()
                country_codes = []

                for file_info in files:
                    if file_info['type'] == 'file':
                        filename = file_info['name']
                        if re.match(r'^[A-Z]{2}$', filename):
                            country_codes.append(filename)

                country_codes.sort()
                print(f"✅ Found {len(country_codes)} country codes via GitHub API")
                return country_codes
            else:
                print("⚠️ GitHub API failed, trying alternative method...")
                return self._fetch_country_codes_fallback()
        except Exception as e:
            print(f"❌ Error fetching country codes: {e}")
            print("🔄 Trying fallback method...")
            return self._fetch_country_codes_fallback()

    def _fetch_country_codes_fallback(self) -> List[str]:
        """Fallback method to get country codes by trying common ones"""
        print("🔄 Using fallback method with common country codes...")
        common_codes = [
            'AE', 'AM', 'AT', 'AU', 'BE', 'CA', 'CF', 'CH', 'CN', 'CW', 'CZ', 'DE',
            'DK', 'ES', 'FI', 'FR', 'GB', 'HK', 'IE', 'IN', 'IT', 'JP', 'KR', 'NL',
            'NO', 'PL', 'RU', 'SE', 'SG', 'TW', 'US', 'ZA'
        ]
        available_codes = []

        for code in common_codes:
            try:
                url = f"{self.base_url}{code}"
                response = requests.head(url, timeout=5)
                if response.status_code == 200:
                    available_codes.append(code)
                    print(f"✅ {code} - Available")
                else:
                    print(f"❌ {code} - Not found")
            except:
                print(f"❌ {code} - Error checking")

        return available_codes

    def fetch_country_data(self, country_code: str) -> Dict:
        """Fetch data for a specific country code"""
        url = f"{self.base_url}{country_code.upper()}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return {
                'country_code': country_code.upper(),
                'country_name': self.get_country_name(country_code),
                'flag_emoji': self.get_flag_emoji(country_code),
                'url': url,
                'content': response.text,
                'status': 'success',
                'content_length': len(response.text)
            }
        except requests.exceptions.RequestException as e:
            return {
                'country_code': country_code.upper(),
                'country_name': self.get_country_name(country_code),
                'flag_emoji': self.get_flag_emoji(country_code),
                'url': url,
                'content': None,
                'status': 'error',
                'error': str(e)
            }

    def fetch_multiple_countries(self, country_codes: List[str]) -> List[Dict]:
        """Fetch data for multiple country codes"""
        results = []
        for code in country_codes:
            print(f"Fetching data for {code}...")
            result = self.fetch_country_data(code)
            results.append(result)
            if result['status'] == 'success':
                print(f"✅ {result['flag_emoji']} {result['country_name']} - {result['content_length']} characters")
            else:
                print(f"❌ {result['flag_emoji']} {result['country_name']} - Error: {result.get('error', 'Unknown error')}")
        return results

    def fetch_all_available_countries(self) -> List[Dict]:
        """Fetch data for all available countries in the repository"""
        country_codes = self.fetch_available_country_codes()
        if not country_codes:
            print("❌ No country codes found!")
            return []
        print(f"\n🌍 Found {len(country_codes)} countries: {', '.join(country_codes)}")
        print(f"\n📥 Starting to fetch data for all countries...\n")
        return self.fetch_multiple_countries(country_codes)

    def save_to_files(self, results: List[Dict], base_filename: str = "country_data"):
        """Save results to separate files for each country"""
        os.makedirs(base_filename, exist_ok=True)
        for result in results:
            if result['status'] == 'success' and result['content']:
                filename = f"{base_filename}/{result['country_code']}_{result['country_name'].replace(' ', '_')}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Country: {result['flag_emoji']} {result['country_name']} ({result['country_code']})\n")
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Content Length: {result['content_length']} characters\n")
                    f.write("-" * 50 + "\n")
                    f.write(result['content'])
                print(f"Saved: {filename}")


# Example usage
if __name__ == "__main__":
    fetcher = CountryDataFetcher()
    print("🌍 PSG Country Data Fetcher")
    print("=" * 50)

    # Fetch all countries from repo
    results = fetcher.fetch_all_available_countries()

    if results:
        print(f"\n📊 Summary:")
        print(f"Total countries processed: {len(results)}")
        print(f"Successful fetches: {sum(1 for r in results if r['status'] == 'success')}")
        print(f"Failed fetches: {sum(1 for r in results if r['status'] == 'error')}")

        print(f"\n💾 Saving data to files...")
        fetcher.save_to_files(results)

        successful = [r for r in results if r['status'] == 'success']
        successful = [r for r in successful if r['country_name'] == 'Fastest Location'] + \
                    [r for r in successful if r['country_name'] != 'Fastest Location']
        configs = []
        if successful:
            print(f"\n🎉 Successfully fetched data for:")
            for r in successful:
                config = build_config(f"{r['flag_emoji']} {r['country_name']}", r["content"])
                configs.append(config)
                #print(f"   {r['flag_emoji']} {r['country_name']} ({r['country_code']}) - {r['content_length']} chars")
            with open("configs.json", "w", encoding="utf-8") as f:
                json.dump(configs, f, indent=4, ensure_ascii=False)
            #print(f"\n📈 Top 5 countries by content size:")
            # top5 = sorted(successful, key=lambda x: x['content_length'], reverse=True)[:5]
            # for r in top5:
            #     print(f"   {r['flag_emoji']} {r['country_name']}: {r['content_length']} characters")

        failed = [r for r in results if r['status'] == 'error']
        if failed:
            print(f"\n❌ Failed to fetch data for:")
            for r in failed:
                print(f"   {r['flag_emoji']} {r['country_name']} ({r['country_code']}) - {r.get('error', 'Unknown error')}")
    else:
        print("❌ No data was fetched. Please check your internet connection and try again.")
