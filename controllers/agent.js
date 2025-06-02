 
import express from "express";
import { catchASyncError } from "../middlewares/catchASyncError.js";
import ErrorHandler from "../middlewares/error.js";
import User from "../models/userSchema.js";
import Donation from "../models/foodSchema.js";

const router = express.Router();


export const agent_dashboard = catchASyncError(async (req, res, next) => {
   
    console.log("user ",req.user)
    const agentId = req.user._id;
    const numAssignedDonations = await Donation.countDocuments({
        agent: agentId,
        status: "assigned",
    });
    const numCollectedDonations = await Donation.countDocuments({
        agent: agentId,
        status: "collected",
    });

    res.status(200).json({
        success: true,
        data: {
            numAssignedDonations,
            numCollectedDonations
        }
    });
});

export const agent_collection_pend = catchASyncError(async (req, res, next) => {
    const pendingCollections = await Donation.find({
        agent: req.user._id,
        status: "assigned",
    }).populate("donor");

    res.status(200).json({
        success: true,
        pendingCollections
    });
});
// export const agent_collection_pend = catchASyncError(async (req, res, next) => {
//     const pendingCollections = await Donation.find({ status: 'assigned' }).populate('donor');
    
//     if (!pendingCollections) {
//         return res.status(404).json({
//             success: false,
//             message: 'No pending collections found'
//         });
//     }

//     res.status(200).json({
//         success: true,
//         pendingCollections
//     });
// });

export const agent_collection_prev = catchASyncError(async (req, res, next) => {
    const previousCollections = await Donation.find({
        agent: req.user._id,
        status: "collected",
    }).populate("donor");

    res.status(200).json({
        success: true,
        previousCollections
    });
});
// export const agent_collection_prev  = catchASyncError(async (req, res, next) => {
//     const previousCollections = await Donation.find({ status: 'collected' }).populate('donor');
    
//     if (!previousCollections) {
//       return res.status(404).json({
//         success: false,
//         message: 'No previous collections found'
//       });
//     }
  
//     res.status(200).json({
//       success: true,
//       previousCollections
//     });
//   });

export const agent_collectionView = catchASyncError(async (req, res, next) => {
    const collectionId = req.params.collectionId;
    const collection = await Donation.findById(collectionId).populate("donor");

    if (!collection) {
        return res.status(404).json({
            success: false,
            message: "Collection not found"
        });
    }

    res.status(200).json({
        success: true,
        collection
    });
});

export const agent_collection_collect = catchASyncError(async (req, res, next) => {
    const collectionId = req.params.collectionId;
   
 
console.log("collection id ", collectionId)
    await Donation.findByIdAndUpdate(collectionId, {
        status: "collected",
        collectionTime: Date.now(),
    });

    
    res.status(200).json({
        success: true,
        message: "Donation collected successfully"
    });
});

export const agent_profile = catchASyncError(async (req, res, next) => {
    res.status(200).json({
        success: true,
        profile: req.user
    });
});

export const agent_profile_update = catchASyncError(async (req, res, next) => {
    const id = req.user._id;
    const updateObj = req.body.agent; // updateObj: {firstName, lastName, gender, address, phone}
    await User.findByIdAndUpdate(id, updateObj);

    res.status(200).json({
        success: true,
        message: "Profile updated successfully"
    });
});

export const agent_googlemaps = catchASyncError(async (req, res, next) => {
    res.status(200).json({
        success: true,
        title: "Google Maps"
    });
});

export default router;
