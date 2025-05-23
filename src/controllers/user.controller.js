import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.models.js"
import { uploadCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import { json } from "express";


const generateAccessTokenAndRefreshTokens = async (userId) =>
{
    try {
        const user = await User.findById(userId)
        const accessToken = await user.generateAccessToken()
        const refreshToken = await user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })
        
        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }
}


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
    // console.log("email", email);

    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    )
    {
        throw new ApiError(400, "All fields are required")
    }
 const existedUser = await User.findOne({
        $or: [{username}, {email}]
 })
    
    if (existedUser) {
        throw new ApiError(409, "User with email or username is exist")
    }
console.log(req.files)
const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }
    
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


const loginUser = asyncHandler(async (req, res) => {
    // req body-> data
    //username or email
    //find the user with given username or email
    //password check
    // access and refresh token
    // send cookie
    const {email, username, password} = req.body

    if (!(username || email)) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne(
        {
            $or: [{ email }, { username }]
        }
    )
    if (!user) {
        throw new ApiError(400, "User does not exist")
    }
    const isPasswordValid = await user.isPasswordCorrect(password) // this password is that we get from body
    if (!isPasswordValid){
        throw new ApiError(401, "Invalid user credentials")
    }
    const { accessToken, refreshToken } =
        await generateAccessTokenAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(201)
    .cookie("accessToken", accessToken)
    .cookie("refreshToken", refreshToken)
    .json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In successfully"
        )
    )
    
})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken)
    .cookie("refreshToken", refreshToken)
    .json(
        new ApiResponse(
            200, {}, "User LoggedOut   successfully"
        )
    )
})
export {
    registerUser,
    loginUser,
    logoutUser
};
