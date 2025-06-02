import express from "express";

import {
  admin_dashboard,
  admin_donation_pending,
  admin_donation_previous,
  admin_donation_view,
  admin_donation_accept,
  admin_donation_reject,
  admin_donation_assign,
  admin_donation_assign_agent,
  admin_dashboard_agents,
  admin_profile,
  admin_profile_update,
  all_agent,
} from "../controllers/admin.js";

import { isAuthorized } from "../middlewares/auth.js";
const router = express.Router();

router.get("/admin/dashboard" ,  admin_dashboard);
router.get("/admin/donations/pending", admin_donation_pending);
router.get("/admin/donations/previous",  admin_donation_previous);
router.get("/admin/donation/view/:donationId", admin_donation_view);
router.post("/admin/donation/accept/:donationId",  admin_donation_accept);
router.post("/admin/donation/reject/:donationId",  admin_donation_reject);
router.post("/admin/donation/assign/:donationId",admin_donation_assign);
router.post("/admin/donation/assignt/:donationId",isAuthorized,  admin_donation_assign_agent);
router.get("/admin/agents",  admin_dashboard_agents);
router.get("/admin/profile",  admin_profile);
router.post("/admin/profile",  admin_profile_update);
router.get("/admin/allagents", all_agent);


export default router;
