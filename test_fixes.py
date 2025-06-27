#!/usr/bin/env python3

from services.data_processor import DataProcessor

dp = DataProcessor()

# Test malware families
print("=== MALWARE FAMILIES ===")
families = dp.get_malware_family_trends()
for family, count in families.items():
    print(f"{family}: {count}")

print("\n=== IOC TIMELINE ===")
timeline = dp.get_ioc_timeline()
print("First 5 days:")
for i in range(5):
    print(f"{timeline['dates'][i]}: IP={timeline['ip_counts'][i]}, Domain={timeline['domain_counts'][i]}, Hash={timeline['hash_counts'][i]}")

print(f"\nTotal timeline length: {len(timeline['dates'])} days")
print(f"Total IP indicators: {sum(timeline['ip_counts'])}")
print(f"Total Domain indicators: {sum(timeline['domain_counts'])}")
print(f"Total Hash indicators: {sum(timeline['hash_counts'])}")
