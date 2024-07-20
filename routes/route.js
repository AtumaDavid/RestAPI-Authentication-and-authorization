const { Router } = require("express");
const { register, stay } = require("../controllers/controller");

const router = Router();

router.get("/", stay);
router.post("/api/auth/register", register);

module.exports = router;
