import pandas as pd

csv_file = "csp_scan_results.csv"

# Read the original CSV
df = pd.read_csv(csv_file)

# Define the exact error messages to remove
unwanted_errors = [
    "UNHANDLED: TargetClosedError: Browser.new_context: Target page, context or browser has been closed",
    "UNHANDLED: Exception: Browser.new_context: Connection closed while reading from the driver"
]

# Keep rows where error is NOT in the unwanted list
df_filtered = df[~df["error"].isin(unwanted_errors)]

# Write back to the same file (overwrite)
df_filtered.to_csv(csv_file, index=False)

print(f"Original rows: {len(df)}")
print(f"Rows removed: {len(df) - len(df_filtered)}")
print(f"Remaining rows: {len(df_filtered)}")
print(f"Updated {csv_file} in place.")