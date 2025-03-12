import React, { useState } from "react";
import axios from "axios";
import URLInput from "../components/URLInput.jsx";
import Result from "../components/Result.jsx";

function Home() {
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const checkURL = async (url) => {
        setLoading(true);
        setError(null);
        setResult(null);
        try {
            const response = await axios.post("http://localhost:8000/predict/", { url });
            setResult(response.data.phishing);
        } catch (error) {
            console.error("Error fetching data:", error);
            setError("Failed to fetch data. Please try again later.");
        }
        setLoading(false);
    };

    return (
        <div className="container text-center mt-5">
            <h2 className="mb-4">🔍 Phishing URL Checker</h2>
            <URLInput onCheck={checkURL} />
            {loading && <p className="text-primary mt-3">Checking...</p>}
            {error && <p className="text-danger mt-3">{error}</p>}
            {!loading && result !== null && <Result status={result} />}
        </div>
    );
}

export default Home;
