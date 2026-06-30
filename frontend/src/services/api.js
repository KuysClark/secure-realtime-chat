import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5000/api/authRouters",
  withCredentials: true, // ✅ cookies only
});

export default api;
