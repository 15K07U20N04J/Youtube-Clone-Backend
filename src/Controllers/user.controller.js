import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../cloudinary.js"
import { ApiResponce } from "../utils/ApiResponce.js"
import jwt from "jsonwebtoken"
import mongoose from "mongoose"

const generateAccessAndRefreshTokens = async (userId) => {

    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }
}

const registerUser = asyncHandler(async (req, res) => {

    // res.status(200).json({
    //     message: "OK"
    // })

    /*
        get user details from fronted
        validation - not empty
        check if user already exists - userName, email
        check for images, check for avtar
        upload them to cloudinary, avatar
        create user object - create entry in db
        remove password and refresh token field from object
        check for user creation
        return responce
    */

    const { userName, fullName, email, password } = req.body

    if (
        [fullName, userName, email, password].some((field) => {
            return field?.trim() === ""
        })
    ) {
        throw new ApiError(400, "Please enter all credentials")
    }

    const existedUser = await User.findOne({
        $or: [{ userName }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User with username or email Already exists")
    }
    // console.table(req.files)
    // console.log(req.files)
    const avatarLocalPath = req.files?.avatar[0].path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, " Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        console.log('hiii');
        throw new ApiError(400, "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        userName: userName.toLowerCase(),
        email,
        password
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while refistering user")
    }

    return res.status(201).json(
        new ApiResponce(200, createdUser, "User registerd successfully")
    )

})

const loginUser = asyncHandler(async (req, res) => {

    /*
        req body -> data
        username or email
        find the user
        password check
        access and refresh token generate
        send cookies
        send responce -> tou are logged in
    */

    const { userName, password, email } = req.body

    if (!userName && !email) {
        throw new ApiError(400, "username or email is required")
    }

    const user = await User.findOne({
        $or: [{ userName }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    console.log(isPasswordValid);

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).
        select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponce(
                200,
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "User logged In Successfully"
            )
        )

})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset:
            {
                refreshToken: 1
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

    return res.
        status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(
            new ApiResponce(200, {}, "User Logged out Successfully")
        )
})

const refreshAccessToken = asyncHandler(async (req, res) => {

    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    // console.log(incomingRefreshToken);

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized Request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
        // console.log(decodedToken);


        const user = await User.findById(decodedToken?._id)
        console.log(user);


        if (!user) {
            throw new ApiError(401, "Invalid Refresh Token")
        }

        console.log(user.refershToken);

        if (incomingRefreshToken !== user?.refershToken) {
            throw new ApiError(401, "Refresh Token is Expired or used")

        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id)


        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponce(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access Token Refreshed"
                )
            )
    } catch (error) {
        console.log('hii');

        throw new ApiError(401, error?.message || "Invaild Refresh Token")
    }
})

const changeCurrentPassword = asyncHandler(async (req, res) => {

    const { oldPassword, newPassword, confNewPassword } = req.body
    // console.log(oldPassword, newPassword, confNewPassword);

    if (newPassword !== confNewPassword) {
        throw new ApiError(401, "Password and confirm password does not match")
    }

    const user = await User.findById(req.user?._id)

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid Old Password")
    }

    user.password = newPassword
    await user.save({ validateBeforeSave: false })

    return res
        .status(200)
        .json(
            new ApiResponce(
                200,
                {},
                "Password Changed Successfully"
            )
        )
})

const getCurrentUser = asyncHandler(async (req, res) => {
    console.log('hii');
    console.log(req.user);


    return res
        .status(200)
        .json(
            new ApiResponce(
                200,
                req.user,
                "Current User fetch succesfully")
        )
})

const updateAccountDetails = asyncHandler(async (req, res) => {

    const { fullName, email } = req.body

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email: email
            }

        },
        { new: true }

    ).select("-password")

    return res
        .status(200)
        .json(
            new ApiResponce(
                200,
                user,
                "Account details updated successfully"
            )
        )

})

const updateUserAvatar = asyncHandler(async (req, res) => {

    const avatarLocalPath = req.file?.path

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        { new: true }
    ).select("-password")

    return res
        .status(200)
        .json(
            new ApiResponce(
                200,
                user,
                "Avatar is updated successfully"
            )
        )
})

const updateUserCoverImage = asyncHandler(async (req, res) => {

    const coverImageLocalPath = req.file?.path

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!coverImage.url) {
        throw new ApiError(400, "Error while uploading on cover image")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        { new: true }
    ).select("-password")

    return res
        .status(200)
        .json(
            new ApiResponce(
                200,
                user,
                "coverImage is updated successfully"
            )
        )
})

const getUserChannelProfile = asyncHandler(async (req, res) => {

    const { username } = req.params
    console.log(username);

    if (!username?.trim()) {
        throw new ApiError(400, "username is missing")
    }
    // User.find({username})

    const channel = await User.aggregate([
        {
            $match: {
                userName: username?.toLowerCase()
            },
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscriber"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscriberTo"
            }
        },
        {
            $addFields: {
                subscriberCount: {
                    $size: "$subscriber"
                },
                channelSubscribedToCount: {
                    $size: "$subscriberTo"
                },
                isSubscribed: {
                    $cond: {
                        if: { $in: [req.user?._id, ["$subscribers.subscriber"]] },
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                userName: 1,
                subscriberCount: 1,
                channelSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1,
            }
        }
    ])

    console.log(channel?.length);

    if (!channel?.length) {
        throw new ApiError(404, "Channel does not exists")
    }

    return res
        .status(200)
        .json(
            new ApiResponce(
                200,
                channel[0],
                "User channel fetched successfully"
            )
        )
})

const getWatchHistory = asyncHandler(async (req, res) => {

    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "Owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        userName: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res
        .status(200)
        .json(
            new ApiResponce(
                200,
                user[0].watchHistory,
                "Watch history fetched successfully"
            )
        )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory
}