import React, { useState } from "react";

function URLInput({ onCheck }) {
    const [url, setUrl] = useState("");

    return (
        <div className="input-group mt-3">
            <input
                type="text"
                className="form-control"
                placeholder="Enter URL"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
            />
            <button className="btn btn-primary" onClick={() => onCheck(url)}>
                Check
            </button>
        </div>
    );
}

export default URLInput;
