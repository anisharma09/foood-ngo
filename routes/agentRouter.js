import express from "express";
import {
  agent_dashboard,
  agent_collection_pend,
  agent_collection_prev,
  agent_collectionView,
  agent_collection_collect,
  agent_profile,
  agent_profile_update,
  agent_googlemaps,
   
} from "../controllers/agent.js";

import { isAuthorized } from "../middlewares/auth.js";
const router = express.Router();

router.get("/agent/dashboard",isAuthorized, agent_dashboard);
router.get("/agent/collections/pending",isAuthorized, agent_collection_pend);
router.get("/agent/collections/previous",isAuthorized, agent_collection_prev);
router.get("/agent/collection/view/:collectionId", agent_collectionView);
router.get("/agent/collection/collect/:collectionId", agent_collection_collect);
router.get("/agent/profile", agent_profile);
router.post("/agent/profile", agent_profile_update);
router.get("/agent/googlemaps", agent_googlemaps);
 

export default router;
