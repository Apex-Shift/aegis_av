
            rule Suspicious_Keyword {
                meta:
                    description = "Detects generic suspicious patterns"
                strings:
                    $malicious_string = "malware_test_string"
                condition:
                    $malicious_string
            }
            