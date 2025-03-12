import React from "react";

function Result({ status }) {
    if (status === null) return null;
    return (
        <div className="mt-3">
            {status ? (
                <p className="text-danger fw-bold">🚨 Phishing Detected!</p>
            ) : (
                <p className="text-success fw-bold">✅ Safe URL</p>
            )}
        </div>
    );
}

export default Result;
