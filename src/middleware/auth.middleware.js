import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import jwt from "jsonwebtoken"
import { User } from "../models/user.model.js"

export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
        // console.log(token);

        if (!token) {
            throw new ApiError(401, "Unauthorized Request")
        }
        // console.log(process.env.ACCESS_TOKEN_SECRET);
        var decodedToken;

        try {
            decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)
        } catch (error) {
            console.log('error is here');

        }
        // console.log('May be start from here');

        // console.log(decodedToken);
        // console.log('what is here');



        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")

        if (!user) {
            // TODO: Discuss About Fronted
            throw new ApiError(401, "Invalid Access Token");

        }
        // console.log(user);


        req.user = user;
        next()

    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid access token")
    }
})