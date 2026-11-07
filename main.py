
from src.email_parser import parse_email
from src.detection_engine import analyze_email


def main():
    email = parse_email(
        "samples/suspicious_email.eml"
    )

    result = analyze_email(email)

    print("\n========== PHISHGUARD SOC ==========")
    print("Email:", email["subject"])
    print("Sender:", email["from"])
    print("Reply-To:", email["reply_to"])

    print("\n========== ANALYSIS ==========")
    print("Risk Score:", result["risk_score"], "/100")
    print("Risk Level:", result["risk_level"])
    print("Total Findings:", result["total_findings"])

    print("\n========== SECURITY FINDINGS ==========")

    for finding in result["findings"]:
        print("\nType:", finding["type"])
        print("Severity:", finding["severity"])
        print("Description:", finding["description"])
        print("Evidence:", finding["evidence"])

    print("\n====================================")


if __name__ == "__main__":
    main()
