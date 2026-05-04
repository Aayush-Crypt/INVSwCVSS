"""
Provides warnings and explanations for insecure ports.
"""

DANGEROUS_PORTS = {
    21: {
        "service": "FTP",
        "risk": "Plaintext authentication can expose credentials."
    },
    23: {
        "service": "Telnet",
        "risk": "Insecure remote access vulnerable to sniffing attacks."
    },
    25: {
        "service": "SMTP",
        "risk": "Can be abused for spam relay and phishing."
    },
    53: {
        "service": "DNS",
        "risk": "May allow DNS amplification attacks if misconfigured."
    },
    110: {
        "service": "POP3",
        "risk": "Unencrypted email authentication risk."
    },
    135: {
        "service": "RPC",
        "risk": "Commonly targeted by worms and malware."
    },
    139: {
        "service": "NetBIOS",
        "risk": "Can expose Windows file sharing services."
    },
    143: {
        "service": "IMAP",
        "risk": "May expose email credentials without encryption."
    },
    445: {
        "service": "SMB",
        "risk": "Major ransomware target (e.g., WannaCry)."
    },
    3306: {
        "service": "MySQL",
        "risk": "Database exposure may lead to data theft."
    },
    3389: {
        "service": "RDP",
        "risk": "Frequently targeted for brute-force attacks."
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "Improperly secured database access risk."
    },
    5900: {
        "service": "VNC",
        "risk": "Remote desktop service vulnerable to unauthorized access."
    }
}


def get_port_warning(port):
    """
    Return warning information for dangerous ports.
    """
    return DANGEROUS_PORTS.get(port)