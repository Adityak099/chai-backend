import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
// Define a new Mongoose schema for a User model with various fields such as:
// username, email, fullName, avatar, coverImage, watchHistory, password and refreshToken.
// Each field has specific data type, some of them are required, some are unique and some have trim or lowercase options.
const userSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowecase: true,
      trim: true,
    },
    fullName: {
      type: String,
      required: true,
      trim: true,
      index: true,
    },
    avatar: {
      type: String, // cloudinary url
      required: true,
    },
    coverImage: {
      type: String, // cloudinary url
    },
    watchHistory: [
      {
        type: Schema.Types.ObjectId,
        ref: "Video",
      },
    ],
    password: {
      type: String,
      required: [true, "Password is required"],
    },
    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true,
  }
);


// Pre-save middleware to hash the password using bcrypt before saving the user document to the database
// This is to ensure that the password is stored securely and not in plaintext.
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 10);
  next();
});


// Method to check if a given plaintext password is correct for the user by comparing it to the hashed password stored in the database
// This is to ensure that the user can only log in with the correct password.
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};


// Method to generate an access token for the user to use for authentication in protected routes
// The access token contains the user's id, email, username, and fullName as payload
// The access token has an expiry time based on the environment variable ACCESS_TOKEN_EXPIRY
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};


// Method to generate a refresh token for the user to use for refreshing the access token
// The refresh token contains the user's id as payload
// The refresh token has an expiry time based on the environment variable REFRESH_TOKEN_EXPIRY
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};
// Export the User model to be used in other parts of the application
export const User = mongoose.model("User", userSchema);
