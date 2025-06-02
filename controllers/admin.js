
import express from "express";
import { catchASyncError } from "../middlewares/catchASyncError.js";
import ErrorHandler from "../middlewares/error.js";
import User from "../models/userSchema.js";
import Donation from "../models/foodSchema.js";

const router = express.Router();

export const admin_dashboard = catchASyncError(async (req, res, next) => {
    const numAdmins = await User.countDocuments({ role: "admin" });
    const numDonors = await User.countDocuments({ role: "donor" });
    const numAgents = await User.countDocuments({ role: "agent" });
    const numPendingDonations = await Donation.countDocuments({ status: "pending" });
    const numAcceptedDonations = await Donation.countDocuments({ status: "accepted" });
    const numAssignedDonations = await Donation.countDocuments({ status: "assigned" });
    const numCollectedDonations = await Donation.countDocuments({ status: "collected" });

    
    res.status(200).json({
        success: true,
        data: {
            numAdmins, 
            numDonors, 
            numAgents, 
            numPendingDonations, 
            numAcceptedDonations, 
            numAssignedDonations, 
            numCollectedDonations
        }
    });
});

export const admin_donation_pending = catchASyncError(async (req, res, next) => {
    try {
        const pendingDonations = await Donation.find({ status: { $in: ["pending", "accepted", "assigned"] } })
            .populate('donor', 'name email');
        res.status(200).json({
            success: true,
            pendingDonations
        });
    } catch (err) {
        console.error('Error fetching pending donations:', err);
        res.status(500).json({
            success: false,
            message: "Some error occurred on the server."
        });
    }
});

export const admin_donation_previous = catchASyncError(async (req, res, next) => {
    const previousDonations = await Donation.find({ status: "collected" }).populate("donor");
    res.status(200).json({
        success: true,
        previousDonations
    });
});

export const admin_donation_view = catchASyncError(async (req, res, next) => {
    const donationId = req.params._Id;
    console.log("donation id",donationId)
    const donation = await Donation.findById(donationId).populate("donor").populate("agent");
    console.log("donation",donation)

    try {
        const donationId = req.params.donationId;
        const donation = await Donation.findById(donationId);
    
        if (!donation) {
          return res.status(404).json({
            success: false,
            message: 'Donation not found',
          });
        }
    
        res.status(200).json({
          success: true,
          donation,
        });
      } catch (error) {
        console.error('Error fetching donation:', error);
        res.status(500).json({
          success: false,
          message: 'Some error occurred on the server.',
          error: error.message,
        });
      }
    })

export const admin_donation_accept = catchASyncError(async (req, res, next) => {
    const donationId = req.params.donationId;
    await Donation.findByIdAndUpdate(donationId, { status: "accepted" });

    res.status(200).json({
        success: true,
        message: "Donation accepted successfully"
    });
});

export const admin_donation_reject = catchASyncError(async (req, res, next) => {
    const donationId = req.params.donationId;
    await Donation.findByIdAndUpdate(donationId, { status: "rejected" });

    res.status(200).json({
        success: true,
        message: "Donation rejected successfully"
    });
});

// export const admin_donation_assign = catchASyncError(async (req, res, next) => {
// //     const donationId = req.params.Id;
// //     const agents = await User.find({ role: "agent" });
// //     const donation = await Donation.findById(donationId).populate("donor");

// //     res.status(200).json({
// //         success: true,
// //         data: {
// //             donation, 
// //             agents
// //         }
// //     });
// // });
// try {
//     const { donationId } = req.params;
//     console.log(`Fetching donation with ID: ${donationId}`);
    
//     const donation = await Donation.findById(donationId).populate('donor');
//     const agents = await User.find({ role: 'agent' });

//     if (!donation) {
//       console.log(`Donation with ID: ${donationId} not found`);
//       return res.status(404).json({ success: false, message: 'Donation not found' });
//     }

//     res.status(200).json({
//       success: true,
//       data: {
//         donation,
//         agents,
//       },
//     });
//   } catch (err) {
//     console.log(`Error fetching donation or agents: ${err.message}`);
//     res.status(500).json({
//       success: false,
//       message: 'Some error occurred on the server.',
//     });
//   }
// });
// export const admin_donation_assign_agent = catchASyncError(async (req, res, next) => {
//     const donationId = req.params.donationId;
//     const agentId = req.body.agentId;
//     console.log("donation assign id ",donationId)
//     const { agent, adminToAgentMsg } = req.body;
//     await Donation.findByIdAndUpdate(donationId, { status: "assigned", agent, adminToAgentMsg });

//     res.status(200).json({
//         success: true,
//         message: "Agent assigned successfully"
//     });
// });
// Fetch donation and agents
export const admin_donation_assign = catchASyncError(async (req, res, next) => {
    try {
      const { donationId } = req.params;
      console.log(`Fetching donation with ID: ${donationId}`);
  
      const donation = await Donation.findById(donationId).populate('donor');
      const agents = await User.find({ role: 'agent' });
  
      if (!donation) {
        console.log(`Donation with ID: ${donationId} not found`);
        return res.status(404).json({ success: false, message: 'Donation not found' });
      }
  
      res.status(200).json({
        success: true,
        data: {
          donation,
          agents,
        },
      });
    } catch (err) {
      console.log(`Error fetching donation or agents: ${err.message}`);
      res.status(500).json({
        success: false,
        message: 'Some error occurred on the server.',
      });
    }
  });
  
  // Assign agent to donation
  export const admin_donation_assign_agent = catchASyncError(async (req, res, next) => {
    try {
      const { donationId } = req.params;
      const { agentId, adminToAgentMsg } = req.body;
  
      console.log(`Assigning agent with ID: ${agentId} to donation with ID: ${donationId}`);
  
      const updatedDonation = await Donation.findByIdAndUpdate(
        donationId,
        { status: "assigned", agent: agentId, adminToAgentMsg , agentName: agentId.name},
        { new: true }
      );
  
      if (!updatedDonation) {
        console.log(`Donation with ID: ${donationId} not found for assignment`);
        return res.status(404).json({ success: false, message: 'Donation not found for assignment' });
      }
  
      res.status(200).json({
        success: true,
        message: "Agent assigned successfully",
      });
    } catch (err) {
      console.log(`Error assigning agent: ${err.message}`);
      res.status(500).json({
        success: false,
        message: 'Some error occurred on the server or select the agent',
      });
    }
  });

export const admin_dashboard_agents = catchASyncError(async (req, res, next) => {
    const agents = await User.find({ role: "agent" });

    res.status(200).json({
        success: true,
        agents
    });
});

export const admin_profile = catchASyncError(async (req, res, next) => {
    res.status(200).json({
        success: true,
        profile: req.user
    });
});

export const admin_profile_update = catchASyncError(async (req, res, next) => {
    const id = req.user._id;
    const updateObj = req.body.admin;
    await User.findByIdAndUpdate(id, updateObj);

    res.status(200).json({
        success: true,
        message: "Profile updated successfully"
    });
});

export const all_agent = catchASyncError(async(req,res,next)=>{
    const agents = await User.find({role:"agent"});
    res.status(200).json({
        success:true,
        agents
    });
})
// export default router;
