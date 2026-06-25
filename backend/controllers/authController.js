const jwt = require("jsonwebtoken");
const {
  signupSchema,
  signinSchema,
  acceptCodeSchema,
  changePasswordSchema,
  acceptFPCodeSchema,
} = require("../middlewares/validator");
const { doHash, doHashValidation, hmacProcess } = require("../utils/hashing");
const pool = require("../db/pool"); // ⬅️ PostgreSQL connection (instead of User model)
const transport = require("../middlewares/sendMail");

// ============================================
// SIGNUP
// ============================================
exports.signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { error, value } = signupSchema.validate({ email, password });

    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }

    // Check if user exists
    const existingUser = await pool.query(
      "SELECT * FROM auth_user WHERE email = $1",
      [email],
    );

    if (existingUser.rows.length > 0) {
      return res.status(401).json({
        success: false,
        message: "User already exists",
      });
    }

    const hashedPassword = await doHash(password, 12);

    // Insert new user
    const result = await pool.query(
      `INSERT INTO auth_user (email, password) VALUES ($1, $2)`,
      [email, hashedPassword],
    );

    res.status(201).json({
      success: true,
      message: "Your account has been created successfully",
      user: result.rows[0],
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// ============================================
// SIGNIN
// ============================================
exports.signin = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { error, value } = signinSchema.validate({ email, password });

    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }

    // Get user with password (no need for select('+password') because we include it in query)
    const result = await pool.query(
      "SELECT uuid, email, password_hash, verified FROM user_profile WHERE email = $1",
      [email],
    );

    const existingUser = result.rows[0];

    if (!existingUser) {
      return res.status(401).json({
        success: false,
        message: "User does not exist!",
      });
    }

    const isPasswordValid = await doHashValidation(
      password,
      existingUser.password_hash,
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const token = jwt.sign(
      {
        userId: existingUser.uuid,
        email: existingUser.email,
        verified: existingUser.verified,
      },
      process.env.TOKEN_SECRET,
    );

    res
      .cookie("Authorization", "Bearer " + token, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV === "production",
        secure: process.env.NODE_ENV === "production",
      })
      .json({
        success: true,
        token,
        message: "Logged in successfully",
      });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// ============================================
// SIGNOUT
// ============================================
exports.signout = async (req, res) => {
  res
    .clearCookie("Authorization")
    .status(200)
    .json({ success: true, message: "Logged out successfully" });
};

// ============================================
// SEND VERIFICATION CODE
// ============================================
exports.sendVerificationCode = async (req, res) => {
  const { email } = req.body;

  try {
    const result = await pool.query(
      "SELECT uuid, email, verified FROM user_profile WHERE email = $1",
      [email],
    );

    const existingUser = result.rows[0];

    if (!existingUser) {
      return res.status(402).json({
        success: false,
        message: "User does not exist",
      });
    }

    if (existingUser.verified) {
      return res.status(402).json({
        success: false,
        message: "You are already verified",
      });
    }

    const codeValue = Math.floor(Math.random() * 100000).toString();

    let info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: existingUser.email,
      subject: "Verification code",
      html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; background: #f9f9f9; }
                        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; }
                        .code { 
                            font-size: 32px; 
                            font-weight: bold; 
                            letter-spacing: 8px;
                            text-align: center;
                            background: #f0f0f0;
                            padding: 20px;
                            margin: 20px 0;
                            border-radius: 8px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Verify Your Email Address</h2>
                        <p>Enter this verification code in the app:</p>
                        <div class="code">${codeValue}</div>
                        <p>This code will expire in <strong>10 minutes</strong>.</p>
                        <p>If you didn't request this code, please ignore this email.</p>
                        <hr>
                        <p style="color: #666; font-size: 12px;">
                            &copy; 2025 jwt practice. All rights reserved.
                        </p>
                    </div>
                </body>
                </html>
            `,
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET,
      );

      await pool.query(
        `UPDATE user_profile 
                 SET verification_code = $1, 
                     verification_code_validation = $2 
                 WHERE uuid = $3`,
        [hashedCodeValue, Date.now(), existingUser.uuid],
      );

      return res.status(200).json({
        success: true,
        message: "Code sent",
      });
    }

    res.status(400).json({
      success: false,
      message: "Code sent failed",
    });
  } catch (error) {
    console.error("Error sending verification code:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// ============================================
// VERIFY VERIFICATION CODE
// ============================================
exports.verifyVerificationCode = async (req, res) => {
  const { email, providedCode } = req.body;

  try {
    const { error, value } = acceptCodeSchema.validate({ email, providedCode });

    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    const codeValue = providedCode.toString();

    const result = await pool.query(
      `SELECT uuid, email, verified, verification_code, verification_code_validation 
             FROM user_profile 
             WHERE email = $1`,
      [email],
    );

    const existingUser = result.rows[0];

    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User does not exist",
      });
    }

    if (
      !existingUser.verification_code ||
      !existingUser.verification_code_validation
    ) {
      return res.status(400).json({
        success: false,
        message: "Verification code not found or expired",
      });
    }

    if (existingUser.verified) {
      return res.status(400).json({
        success: false,
        message: "You are already verified",
      });
    }

    const currentTime = Date.now();
    const codeAge = currentTime - existingUser.verification_code_validation;
    const FIVE_MINUTES = 5 * 60 * 1000;

    if (codeAge > FIVE_MINUTES) {
      return res.status(400).json({
        success: false,
        message: "Code has expired!",
      });
    }

    const hashedCodeValue = hmacProcess(
      codeValue,
      process.env.HMAC_VERIFICATION_CODE_SECRET,
    );

    if (hashedCodeValue !== existingUser.verification_code) {
      return res.status(400).json({
        success: false,
        message: "Invalid verification code",
      });
    }

    await pool.query(
      `UPDATE user_profile 
             SET verified = true, 
                 verification_code = NULL, 
                 verification_code_validation = NULL 
             WHERE uuid = $1`,
      [existingUser.uuid],
    );

    return res.status(200).json({
      success: true,
      message: "Your account has been verified successfully!",
    });
  } catch (error) {
    console.error("Verification error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// ============================================
// CHANGE PASSWORD
// ============================================
exports.changePassword = async (req, res) => {
  const { userId, verified } = req.user;
  const { oldPassword, newPassword } = req.body;

  try {
    const { error, value } = changePasswordSchema.validate({
      oldPassword,
      newPassword,
    });

    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message,
      });
    }

    if (!verified) {
      return res.status(401).json({
        success: false,
        message: "You are not a verified user!",
      });
    }

    const result = await pool.query(
      "SELECT uuid, password_hash FROM user_profile WHERE uuid = $1",
      [userId],
    );

    const existingUser = result.rows[0];

    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User does not exist",
      });
    }

    const isPasswordValid = await doHashValidation(
      oldPassword,
      existingUser.password_hash,
    );

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Old password is incorrect",
      });
    }

    const hashedPassword = await doHash(newPassword, 12);

    await pool.query(
      "UPDATE user_profile SET password_hash = $1 WHERE uuid = $2",
      [hashedPassword, userId],
    );

    return res.status(200).json({
      success: true,
      message: "Password updated successfully!",
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Server error",
    });
  }
};

// ============================================
// SEND FORGOT PASSWORD CODE
// ============================================
exports.sendForgotPasswordCode = async (req, res) => {
  const { email } = req.body;

  try {
    const result = await pool.query(
      "SELECT uuid, email FROM user_profile WHERE email = $1",
      [email],
    );

    const existingUser = result.rows[0];

    if (!existingUser) {
      return res.status(402).json({
        success: false,
        message: "User does not exist",
      });
    }

    const codeValue = Math.floor(Math.random() * 100000).toString();

    let info = await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: existingUser.email,
      subject: "Forgot password code",
      html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; background: #f9f9f9; }
                        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; }
                        .code { 
                            font-size: 32px; 
                            font-weight: bold; 
                            letter-spacing: 8px;
                            text-align: center;
                            background: #f0f0f0;
                            padding: 20px;
                            margin: 20px 0;
                            border-radius: 8px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Reset Your Password</h2>
                        <p>Enter this Forgot Password code in the app:</p>
                        <div class="code">${codeValue}</div>
                        <p>This code will expire in <strong>10 minutes</strong>.</p>
                        <p>If you didn't request this code, please ignore this email.</p>
                        <hr>
                        <p style="color: #666; font-size: 12px;">
                            &copy; 2025 jwt practice. All rights reserved.
                        </p>
                    </div>
                </body>
                </html>
            `,
    });

    if (info.accepted[0] === existingUser.email) {
      const hashedCodeValue = hmacProcess(
        codeValue,
        process.env.HMAC_VERIFICATION_CODE_SECRET,
      );

      await pool.query(
        `UPDATE user_profile 
                 SET forgot_password_code = $1, 
                     forgot_password_code_validation = $2 
                 WHERE uuid = $3`,
        [hashedCodeValue, Date.now(), existingUser.uuid],
      );

      return res.status(200).json({
        success: true,
        message: "Code sent",
      });
    }

    res.status(400).json({
      success: false,
      message: "Code sent failed",
    });
  } catch (error) {
    console.error("Error sending forgot password code:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// ============================================
// VERIFY FORGOT PASSWORD CODE
// ============================================
exports.verifyForgotPasswordCode = async (req, res) => {
  const { email, providedCode, newPassword } = req.body;

  try {
    const { error, value } = acceptFPCodeSchema.validate({
      email,
      providedCode,
      newPassword,
    });

    if (error) {
      return res.status(400).json({
        success: false,
        message: error.details[0].message,
      });
    }

    const codeValue = providedCode.toString();

    const result = await pool.query(
      `SELECT uuid, email, forgot_password_code, forgot_password_code_validation 
             FROM user_profile 
             WHERE email = $1`,
      [email],
    );

    const existingUser = result.rows[0];

    if (!existingUser) {
      return res.status(404).json({
        success: false,
        message: "User does not exist",
      });
    }

    if (
      !existingUser.forgot_password_code ||
      !existingUser.forgot_password_code_validation
    ) {
      return res.status(400).json({
        success: false,
        message: "Verification code not found or expired",
      });
    }

    const currentTime = Date.now();
    const codeAge = currentTime - existingUser.forgot_password_code_validation;
    const FIVE_MINUTES = 5 * 60 * 1000;

    if (codeAge > FIVE_MINUTES) {
      return res.status(400).json({
        success: false,
        message: "Code has expired!",
      });
    }

    const hashedCodeValue = hmacProcess(
      codeValue,
      process.env.HMAC_VERIFICATION_CODE_SECRET,
    );

    if (hashedCodeValue !== existingUser.forgot_password_code) {
      return res.status(400).json({
        success: false,
        message: "Invalid verification code",
      });
    }

    const hashedPassword = await doHash(newPassword, 12);

    await pool.query(
      `UPDATE user_profile 
             SET password_hash = $1, 
                 verified = true, 
                 forgot_password_code = NULL, 
                 forgot_password_code_validation = NULL 
             WHERE uuid = $2`,
      [hashedPassword, existingUser.uuid],
    );

    return res.status(200).json({
      success: true,
      message: "Password changed successfully!",
    });
  } catch (error) {
    console.error("Verification error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
