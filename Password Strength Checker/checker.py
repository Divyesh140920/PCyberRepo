import re

def check_strength(password):
    strength = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        strength += 2
    elif len(password) >= 8:
        strength += 1
        feedback.append("Consider using 12+ characters for stronger security.")
    else:
        feedback.append("Password is too short. Use at least 8 characters.")

    # Uppercase & lowercase
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        strength += 1
    else:
        feedback.append("Mix upper and lower case letters.")

    # Numbers
    if re.search(r"\d", password):
        strength += 1
    else:
        feedback.append("Add some numbers to your password.")

    # Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    else:
        feedback.append("Add special characters like !, @, #.")

    # Common patterns
    common_passwords = ['password', '123456', 'admin', 'qwerty', 'iloveyou']
    if password.lower() in common_passwords:
        feedback.append("Avoid common passwords.")
        strength = 0

    return strength, feedback


if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    strength, suggestions = check_strength(pwd)

    print(f"\nPassword Strength Score: {strength}/6")
    if suggestions:
        print("Suggestions to improve your password:")
        for s in suggestions:
            print(f"- {s}")
    else:
        print("Your password is strong!")
