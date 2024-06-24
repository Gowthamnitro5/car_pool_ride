import bcrypt from "bcryptjs";
import User from "../models/User.js";
import jwt from "jsonwebtoken";

export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    // Log the request body for debugging
    console.log("Request body:", req.body);

    // Check if all required fields are present
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "Name, email, and password are required" });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const newUser = new User({
      name: name,
      email: email,
      password: hash
    });
    await newUser.save();

    const accessToken = jwt.sign(
      { id: newUser._id, isAdmin: newUser.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
    );

    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day expiration
      sameSite: "strict"
    };

    const { password: _, isAdmin, ...otherDetails } = newUser._doc;
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .json({ user: { ...otherDetails }, isAdmin });
  } catch (err) {
    console.error("Registration error:", err);
    next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Wrong email or password" });
    }

    const accessToken = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
    );

    const options = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day expiration
      sameSite: "strict"
    };

    const { password: _, isAdmin, ...otherDetails } = user._doc;
    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .json({ user: { ...otherDetails }, isAdmin });
  } catch (err) {
    console.error("Login error:", err);
    next(err);
  }
};

export const logout = async (req, res, next) => {
  try {
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: true
    });
    res.status(200).json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    next(err);
  }
};
