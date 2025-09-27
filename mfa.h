#ifndef MFA_H
#define MFA_H

// Generate a 6-digit MFA code for `username`.
// Stores the code and state in-memory and writes the code to Demo/mfa_<username>.txt
// expiry_seconds: number of seconds until the code expires (e.g., 120).
// Returns 0 on success, -1 on error.
int mfa_generate(const char *username, int expiry_seconds);

// Verify a previously generated MFA code for `username`.
// Returns:
//   1  -> code correct (and will be consumed/removed)
//   0  -> code incorrect (attempts decremented)
//  -1  -> no code or expired
//  -2  -> locked (no attempts left)
int mfa_verify(const char *username, int code);

// Remove stored MFA entry and its file (if any).
void mfa_cleanup(const char *username);

// Get remaining attempts for username, or -1 if no entry.
int mfa_get_attempts(const char *username);

// Get seconds left until expiry, or -1 if no entry.
int mfa_get_time_left(const char *username);

#endif // MFA_H
