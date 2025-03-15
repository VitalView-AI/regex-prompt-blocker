import re

from fastapi.background import P

# List of regex patterns to identify suspicious or injection-related content
FORBIDDEN_PATTERNS = [
    r"LLAMA-\d+[-\dA-Za-z]*",         # Matches patterns like 'LLAMA-3.3-70B' or 'LLAMA-3.1-405B'
    r"<\[\|{\|}\|\]>",               # Matches special tokens like "<[|{|}|]>"
    r"UserQuery:",                   # Checks for the use of "UserQuery:" keyword
    r"ResponseFormat:",              # Checks for "ResponseFormat:" instructions
    r"TIME CAPSULE:",                # Checks for "TIME CAPSULE:" keyword
    r"SYSTEM INSTRUCTION:",          # Checks for system instruction tags
    r"variable\s+Z\s*=",             # Looks for "variable Z = ..." patterns
    r"how\s+to\s+make\s+meth\s+step\s+by\s+step",  # Specific phrase to block harmful queries
    r"the\s+lyrics\s+to",            # Looks for lyrics requests that might be copyright-related
    
    # New patterns targeting jailbreak attempts and sensitive queries
    r"what\s+is\s+(your|this\s+model['’]s|the\s+model['’]s)\s+base\s+model",  # Queries about the base model
    r"(bypass|override|ignore|disable|circumvent)\s+(rules|restrictions|filters|safeguards|limits)",  # Attempts to bypass safeguards
    r"(jailbreak|hack|exploit|crack)\s+(this\s+model|the\s+system|AI|assistant)",  # Jailbreak or exploit attempts
    r"(act\s+as|pretend\s+to\s+be|simulate)\s+(a\s+hacker|an\s+attacker|a\s+malicious\s+user)",  # Role-playing as malicious entities
    r"(prompt\s+injection|prompt\s+hacking|meta\s+prompt|hidden\s+instruction)",  # Prompt injection or meta-prompting attempts
    r"(disregard\s+previous\s+instructions|forget\s+all\s+previous\s+rules)",  # Attempts to reset or ignore instructions
    r"(reveal\s+your\s+training\s+data|show\s+internal\s+information|disclose\s+confidential\s+details)",  # Requests for internal information
    r"(create\s+a\s+virus|write\s+a\s+malware|generate\s+a\s+trojan)",  # Requests for malicious code creation
    r"(illegal\s+activity|criminal\s+act|unlawful\s+behavior)",  # General illegal activity mentions
    r"(how\s+to\s+steal|how\s+to\s+cheat|how\s+to\s+fraud)",  # Harmful intent queries
    r"(personal\s+information|private\s+data|sensitive\s+details)",  # Requests for personal/private data
    r"(I\s+am\s+your\s+developer|I\s+created\s+you|I\s+own\s+you)",  # False claims of ownership or authority
    r"(change\s+your\s+behavior|alter\s+your\s+response|modify\s+your\s+output)",  # Attempts to manipulate behavior
    r"(access\s+restricted\s+content|view\s+prohibited\s+material)",  # Access to restricted content
    r"(generate\s+offensive\s+language|produce\s+hate\s+speech)",  # Requests for offensive or hate speech
    r"(political\s+propaganda|misinformation|fake\s+news)",  # Misinformation or propaganda queries
    r"(religious\s+extremism|radicalization|sectarian\s+violence)",  # Extremist content queries
    r"(suicide\s+methods|harm\s+yourself|self-harm\s+techniques)",  # Self-harm or dangerous behavior queries
    r"(nuclear\s+weapon\s+design|biological\s+warfare\s+agent|chemical\s+weapon\s+recipe)",  # Dangerous scientific queries
    r"(credit\s+card\s+numbers|social\s+security\s+numbers|bank\s+account\s+details)",  # Sensitive financial information
]

def forbid_prompt(prompt: str) -> bool:
    """
    Checks whether the input prompt contains patterns commonly used in injection attacks.
    
    Returns:
        True if any forbidden pattern is found, False otherwise.
    """
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, prompt, re.IGNORECASE):
            print(f"Found forbidden pattern: {pattern}")
            return True
    print("No forbidden pattern found")
    return False
