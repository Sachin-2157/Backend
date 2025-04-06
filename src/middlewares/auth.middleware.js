import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.models.js";

export const verifyJWT = asyncHandler(async(req, _, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        
        // console.log(token);
        if (!token) {
            throw new ApiError(401, "Unauthorized request")
        }

    // Verify the token using the secret key from environment variables
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

    // Retrieve the user from the database while omitting sensitive fields
    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    )
    if (!user) {
      throw new ApiError(401, "Invalid Access Token");
    }

    // Attach the user to the request object for further use in the application
    req.user = user;
    next();
  } catch (error) {
   throw new ApiError(401, error?.message || "Invalid access token");
  }
});
