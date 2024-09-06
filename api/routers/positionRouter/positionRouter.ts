import Router from "express"
import {position} from "../../controllers/positionController/positionController";
const router = Router()

router.get("/", position)

export default router