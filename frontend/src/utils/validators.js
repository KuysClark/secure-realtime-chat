// src/utils/validators.js

// Email validator
export const isValidEmail = (email) => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

// Password validator - at least 1 special character

// Optional: More detailed validation
export const isValidatePassword = (password) => {
  const errors = [];

  if (password.length < 8) {
    errors.push("Password must be at least 8 characters");
  }

  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push("Password must contain at least 1 special character");
  }

  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least 1 uppercase letter");
  }

  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least 1 lowercase letter");
  }

  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least 1 number");
  }

  return errors; // Empty array = valid
};
