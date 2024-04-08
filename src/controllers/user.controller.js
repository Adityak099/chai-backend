import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

// import bcrypt from "bcryptjs";

const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access tokens"
    );
  }
};

//code for registring user----
const registerUser = asyncHandler(async (req, res) => {
  // get user details from frontend
  // validation - not empty
  // check if user already exists: username, email
  // check for images, check for avatar
  // upload them to cloudinary, avatar
  // create user object - create entry in db
  // remove password and refresh token field from response
  // check for user creation
  // return res

  try {
    const { fullName, email, username, password } = req.body;
    console.log("email: ", email);

    if (!(fullName || email || username || password)) {
      return res
        .status(400)
        .json(new ApiError(400, "All fields are  required"));
    }

    const existedUser = await User.findOne({
      $or: [{ username }, { email }],
    });

    if (existedUser) {
      throw new ApiError(409, "User with email or username already existttt");
    }
    //consol.log(req.files)
    const avatarLocalPAth = req.files?.avatar[0]?.path;
    // console.log("avatarLocalPAth: ", avatarLocalPAth);
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    // let coverImageLocalPath;``
    if (!avatarLocalPath) {
      throw new ApiError(400, "Avatar file is required");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    // console.log("avatar: ", avatar);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
      throw new ApiError(409, "Avatar file is required");
    }

    const user = await User.create({
      fullName,
      avatar: avatar.url,
      coverImage: coverImage?.url || "",
      email,
      password,
      username: username.toLowerCase(),
    });

    const createdUser = await User.findById(user._id).select(
      "-password -refreshToken" //minus sign is used to remove the password and refreshToken from the response body.["-password"]);
    );

    if (!createdUser) {
      throw new ApiError(
        500,
        "Sometthing went wrong while registering the user"
      );
    }

    return res
      .status(201)
      .json(new ApiResponse(200, createdUser, "User registered Successfully"));
  } catch (error) {
    throw new ApiError(500, "Failed to create user");
  }
});

//code for login user----
const loginUser = asyncHandler(async (req, res) => {
  //req body -> date
  //username or email
  //find the user
  //password check kro
  //access and refresh token generate
  //send cookies

  const { email, username, password } = req.body;

  //below code check the username or email is empty or not.
  if (!username || !email) {
    throw new ApiError(400, "Username or password is required");
  }

  // Here is an alternative of above code based on logic discussed in video:
  /*if (!username && !email) {
    throw new ApiError(400, "username or email is required");
  }*/

  //below code find the user on the basis of username or email.
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  //below code check the password is correct or not.
  const ispasswordValid = await user.isPasswordCorrect(password);

  if (!ispasswordValid) {
    throw new ApiError(401, "Invalid User Credentials");
  }

  //generate access and refresh tokens
  const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User Logged In Successfully"
      )
    );
});

//code for logout user----

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: "undefined",
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  //below code clear the cookies from the browser.
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User Logged Out Successfully"));
});

//exporting the functions to be used in other files-----
export { registerUser, loginUser, logoutUser };
