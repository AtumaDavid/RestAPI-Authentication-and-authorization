const { Router } = require("express");
const { register, stay, login } = require("../controllers/controller");

const router = Router();

router.get("/", stay);
router.post("/api/auth/register", register);
router.post("/api/auth/login", login);

module.exports = router;
