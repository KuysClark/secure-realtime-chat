import { create } from "zustand";
import api from "../services/api";
import toast from "react-hot-toast";
import { isValidEmail, isValidatePassword } from "../utils/validators";

const useSignupStore = create((set) => ({
  isLoading: false,

  signup: async (email, password, confirmPassword, username) => {
    set({ isLoading: true });

    try {
      // Frontend validations
      const passwordErrors = isValidatePassword(password);

      if (passwordErrors.length > 0) {
        toast.error(passwordErrors[0]);
        return;
      }

      if (password !== confirmPassword) {
        toast.error("Passwords do not match");
        return;
      }

      if (!isValidEmail(email)) {
        toast.error("Invalid email format");
        return;
      }

      // Debug request body
      console.log("Sending data:", {
        email,
        username,
        password,
      });

      // API Request
      const res = await api.post("/signup", {
        email,
        password,
        username,
        confirmPassword,
      });

      toast.success("Account created successfully!");

      console.log("Response:", res.data);

      return res.data;
    } catch (error) {
      console.error("Signup Error:", error);

      if (error.response) {
        console.error("Status:", error.response.status);
        console.error("Response:", error.response.data);

        toast.error(error.response.data?.message || "Signup failed");
      } else {
        toast.error(error.message || "Something went wrong");
      }

      throw error;
    } finally {
      set({ isLoading: false });
    }
  },
}));

export default useSignupStore;
