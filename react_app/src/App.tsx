import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  BrowserRouter as Router,
  Route,
  Routes,
  Link,
  useLocation,
} from "react-router-dom";

const App = () => {
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [uploadMessage, setUploadMessage] = useState<string>("");

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

  const uploadFile = async () => {
    if (!file) {
      alert("No file selected");
      return;
    }
  
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
        console.error("Full error:", error);
        
        setUploadMessage(
          error.response?.data?.error || "Failed to upload file"
        );
      } else {
        console.error("Unexpected error:", error);
        setUploadMessage("Failed to upload file");
      }
    }
  };
  return (
    <Router>
      <TokenHandler />
      <div>
        <h1>Google OAuth 2.0 with Flask and React</h1>
        <nav>
          <ul>
            <li>
              <Link to="/">Home</Link>
            </li>
            {!authToken && (
              <li>
                <button onClick={login}>Login with Google</button>
              </li>
            )}
            {authToken && (
              <li>
                <button onClick={() => setAuthToken(null)}>Logout</button>
              </li>
            )}
          </ul>
        </nav>

        <Routes>
          <Route
            path="/"
            element={
              <>
                <h2>Welcome to the Google OAuth 2.0 Example</h2>
                {authToken ? (
                  <>
                    <h3>Authenticated</h3>
                    <input type="file" onChange={handleFileChange} />
                    <button onClick={uploadFile}>Upload File</button>
                    {uploadMessage && <p>{uploadMessage}</p>}
                  </>
                ) : (
                  <p>Please log in first to upload a file.</p>
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
