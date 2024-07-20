const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports.stay = async (req, res) => {
  res.send("auth auth");
};

module.exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(422).json({ message: "please fill in all fields" }); //Unprocessable Entity
    }

    if (await User.findOne({ email })) {
      return res.status(409).json({ message: "Email already exists" }); //Status Code: Conflict
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.insert({
      name,
      email,
      password: hashedPassword,
    });

    return res
      .status(201) //created
      .json({ message: "user registered successfully", id: newUser._id });
  } catch (error) {
    return res.status(500).json({ message: error.message }); //Internal Server Error
  }
};
