import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  BrowserRouter as Router,
  Route,
  Routes,
  Link,
  useLocation,
} from "react-router-dom";

const App: React.FC = () => {
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploadMessage, setUploadMessage] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Custom hook to parse URL parameters
  const useQuery = () => {
    return new URLSearchParams(useLocation().search);
  };

  // Component to handle token extraction
  const TokenHandler: React.FC = () => {
    const query = useQuery();
    const accessToken = query.get("access_token");

    useEffect(() => {
      if (accessToken) {
        setAuthToken(accessToken);
        // Remove the token from URL to prevent re-parsing
        window.history.replaceState({}, document.title, "/");
      }
    }, [accessToken]);

    return null;
  };

  const login = async () => {
    try {
      window.location.href = "http://localhost:5000/login";
    } catch (error) {
      console.error("Login failed", error);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      setFile(e.target.files[0]);
    }
  };

  const removeFile = () => {
    setFile(null);
    setUploadMessage("");
    setError(null);
  };

  const uploadFile = async () => {
    if (!file) {
      alert("No file selected");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await axios.post(
        "http://localhost:5000/upload",
        formData,
        {
          withCredentials: true,
          headers: {
            "Content-Type": "multipart/form-data",
            "Authorization": `Bearer ${authToken}`,
          },
        }
      );

      setUploadMessage(response.data.message || "File uploaded successfully");
      
    } catch (error) {
      if (axios.isAxiosError(error)) {
        console.error("Upload error details:", error.response?.data);
        setError(error.response?.data?.error || "Failed to upload file");
      } else {
        console.error("Unexpected error:", error);
        setError("Failed to upload file");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Router>
      <TokenHandler />
      <div style={{ padding: "2rem", fontFamily: "Arial, sans-serif" }}>
        <h1 style={{ textAlign: "center", color: "#333" }}>Google OAuth 2.0 with Flask and React</h1>
        <nav style={{ marginBottom: "2rem", textAlign: "center" }}>
          <ul style={{ listStyle: "none", padding: 0 }}>
            <li style={{ display: "inline", marginRight: "1rem" }}>
              <Link to="/" style={{ textDecoration: "none", color: "#007BFF" }}>Home</Link>
            </li>
            {!authToken && (
              <li style={{ display: "inline" }}>
                <button
                  onClick={login}
                  style={{
                    backgroundColor: "#007BFF",
                    color: "white",
                    border: "none",
                    padding: "0.5rem 1rem",
                    cursor: "pointer"
                  }}
                >
                  Login with Google
                </button>
              </li>
            )}
            {authToken && (
              <li style={{ display: "inline" }}>
                <button
                  onClick={() => setAuthToken(null)}
                  style={{
                    backgroundColor: "#dc3545",
                    color: "white",
                    border: "none",
                    padding: "0.5rem 1rem",
                    cursor: "pointer"
                  }}
                >
                  Logout
                </button>
              </li>
            )}
          </ul>
        </nav>

        <Routes>
          <Route
            path="/"
            element={
              <>
                <h2 style={{ textAlign: "center", color: "#333" }}>Welcome to the Google OAuth 2.0 Example</h2>
                {authToken ? (
                  <div style={{ textAlign: "center" }}>
                    <h3>Authenticated</h3>
                    {file && (
                      <div style={{ marginBottom: "1rem" }}>
                        <strong>Selected File:</strong> {file.name}
                        <button
                          onClick={removeFile}
                          style={{
                            marginLeft: "1rem",
                            backgroundColor: "#ffc107",
                            color: "black",
                            border: "none",
                            padding: "0.2rem 0.5rem",
                            cursor: "pointer"
                          }}
                        >
                          Remove File
                        </button>
                      </div>
                    )}
                    <input type="file" onChange={handleFileChange} style={{ marginBottom: "1rem" }} />
                    <button
                      onClick={uploadFile}
                      disabled={loading}
                      style={{
                        backgroundColor: loading ? "#6c757d" : "#28a745",
                        color: "white",
                        border: "none",
                        padding: "0.5rem 1rem",
                        cursor: loading ? "not-allowed" : "pointer"
                      }}
                    >
                      {loading ? "Uploading..." : "Upload File"}
                    </button>
                    {uploadMessage && <p style={{ color: "green" }}>{uploadMessage}</p>}
                    {error && <p style={{ color: "red" }}>{error}</p>}
                  </div>
                ) : (
                  <p style={{ textAlign: "center" }}>Please log in first to upload a file.</p>
                )}
              </>
            }
          />
        </Routes>
      </div>
    </Router>
  );
};

export default App;
