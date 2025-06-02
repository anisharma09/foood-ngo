import express from "express";
import { catchASyncError } from "../middlewares/catchASyncError.js";
import ErrorHandler from "../middlewares/error.js";
import User from "../models/userSchema.js";
import Donation from "../models/foodSchema.js";

const router = express.Router();

export const donor_dashboard = catchASyncError(async (req, res, next) => {
  try {
    console.log("req.user donate", req.user);

    const donorId = req.user._id;
    console.log("id", donorId);

    const numCollectedDonations = await Donation.countDocuments({
      donor: donorId,
      status: "collected",
    });
    const numPendingDonations = await Donation.countDocuments({
      donor: donorId,
      status: "pending",
    });
    const numAcceptedDonations = await Donation.countDocuments({
      donor: donorId,
      status: "accepted",
    });
    const numAssignedDonations = await Donation.countDocuments({
      donor: donorId,
      status: "assigned",
    });

    res.status(200).json({
      success: true,
      numCollectedDonations,
      numPendingDonations,
      numAcceptedDonations,
      numAssignedDonations,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false,
      message: "Some error occurred on the server.",
    });
  }
});

export const donor_donate = catchASyncError(async (req, res, next) => {
  try {
    const { donation } = req.body;

    if (!donation) {
      return res.status(400).json({
        success: false,
        message: "Donation data is required.",
      });
    }

    console.log("Received donation data:", donation);

    // Ensure that the donor ID is properly assigned
    donation.status = "pending";
    donation.donor = req.user._id; // Assuming the donor ID is stored in req.user._id

    console.log("Modified donation data:", donation);

    const newDonation = new Donation(donation);

    await newDonation.save();

    res.status(200).json({
      success: true,
      message: "Donation request sent successfully",
    });
  } catch (err) {
    console.error("Error in donor_donate:", err);

    // Send an error response with specific error message
    res.status(500).json({
      success: false,
      message: "Some error occurred on the server.",
      error: err.message,
    });
  }
});

export const donor_donation_pend = catchASyncError(async (req, res, next) => {
  try {
    const pendingDonations = await Donation.find({
      donor: req.user._id,
      status: ["pending", "rejected", "accepted", "assigned"],
    }).populate("agent");
    res.status(200).json({
      success: true,
      pendingDonations,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false,
      message: "Some error occurred on the server.",
    });
  }
});

export const donor_donation_prev = catchASyncError(async (req, res, next) => {
  try {
    const previousDonations = await Donation.find({
      donor: req.user._id,
      status: "collected",
    }).populate("agent");
    res.status(200).json({
      success: true,
      previousDonations,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false,
      message: "Some error occurred on the server.",
    });
  }
});

export const donor_donation_deleterejected = catchASyncError(
  async (req, res, next) => {
    try {
      const donationId = req.params.donationId;
      await Donation.findByIdAndDelete(donationId);
      res.status(200).json({
        success: true,
        message: "Donation deleted successfully",
      });
    } catch (err) {
      console.log(err);
      res.status(500).json({
        success: false,
        message: "Some error occurred on the server.",
      });
    }
  }
);

export const donor_profile = catchASyncError(async (req, res, next) => {
  res.status(200).json({
    success: true,
    profile: req.user,
  });
});

export const donor_profile_update = catchASyncError(async (req, res, next) => {
  try {
    const id = req.user._id;
    const updateObj = req.body.donor; // updateObj: {firstName, lastName, gender, address, phone}
    await User.findByIdAndUpdate(id, updateObj);
    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      success: false,
      message: "Some error occurred on the server.",
    });
  }
});
