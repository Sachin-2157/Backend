import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.models.js"
import { uploadCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import { json } from "express";
const registerUser = asyncHandler(async (req, res) => {
    //   1. require details form frontend
    //   2. validation - not empty
    //   3. check if user aldeady exists: username, email
    //   4. check for imges, check for avatar
    //   5. upload them to cloudinary, avatar
    //   6. create user object - create entry in db
    //   7. remove password and refresh token field from response 
    //   8. check  for user creation
    //   9. return response
    
    
    const {fullName, email, username, password} = req.body
    console.log("email", email);

    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    )
    {
        throw new ApiError(400, "All fields are required")
    }
 const existedUser = User.findOne({
        $or: [{username}, {email}]
 })
    
    if (existedUser) {
        throw new ApiError(409, "User with email or username is exist")
    }

const avatarLocalPath = req.files?.avatar[0]?.path
    const coverImageLocalPath = req.files?.coverImage[0]?.path;
    
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadCloudinary(avatarLocalPath)
    const coverImage = await uploadCloudinary(coverImageLocalPath)
    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

  const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
  })
    
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }
    return res.status(201, json(
        new ApiResponse(200, createdUser, "User Registered successfully")
    ))
});

export { registerUser };
