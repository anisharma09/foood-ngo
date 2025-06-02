import express from "express";

import {    
    donor_dashboard,
    donor_donate,
    donor_donation_pend,
    donor_donation_prev,
    donor_donation_deleterejected,
    donor_profile,
    donor_profile_update,

} from "../controllers/doner.js";
 
import { isAuthorized } from "../middlewares/auth.js";
const router = express.Router();

router.get("/doner/dashboard",isAuthorized,  donor_dashboard);
router.post("/doner/donate",isAuthorized,  donor_donate);
router.get("/doner/donations/pending",isAuthorized, donor_donation_pend);
router.get("/doner/donations/previous",isAuthorized,donor_donation_prev);
router.get("/doner/donation/deleteRejected/:donationId",isAuthorized, donor_donation_deleterejected);
router.get("/doner/profile",  donor_profile);
router.post("/doner/profile",  donor_profile_update);




export default router;
