import React from "react";
import useSignupStore from "../store/signup_page";

function SignupPage() {
  const { isLoading, signup } = useSignupStore();

  const [email, setEmail] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [username, setUsername] = React.useState("");

  const [showPassword, setShowPassword] = React.useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = React.useState(false);

  const Submit = () => {
    signup(email, password, confirmPassword, username);
  };

  return (
    <div className="min-h-screen bg-base-200 flex items-center justify-center p-4">
      <div className="card w-full max-w-md bg-base-100 shadow-2xl">
        <div className="card-body">
          <h1 className="text-3xl font-bold text-center">Sign Up</h1>

          <form className="space-y-4 mt-4">
            {/* Username */}
            <input
              type="text"
              placeholder="Enter your name"
              className="input input-bordered w-full"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />

            {/* Email */}
            <input
              type="email"
              placeholder="Enter your email"
              className="input input-bordered w-full"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />

            {/* Password */}
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                placeholder="Create password"
                className="input input-bordered w-full pr-16"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />

              <button
                type="button"
                className="absolute right-2 top-2 text-sm btn btn-ghost btn-xs"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? "Hide" : "Show"}
              </button>
            </div>

            {/* Confirm Password */}
            <div className="relative">
              <input
                type={showConfirmPassword ? "text" : "password"}
                placeholder="Confirm password"
                className="input input-bordered w-full pr-16"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />

              <button
                type="button"
                className="absolute right-2 top-2 text-sm btn btn-ghost btn-xs"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? "Hide" : "Show"}
              </button>
            </div>

            <button
              type="button"
              className="btn btn-primary w-full"
              onClick={Submit}
              disabled={isLoading}
            >
              {isLoading ? "Creating..." : "Create Account"}
            </button>
          </form>

          <p className="text-center text-sm mt-4">
            Already have an account?{" "}
            <a href="#" className="link link-primary">
              Login
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}

export default SignupPage;
