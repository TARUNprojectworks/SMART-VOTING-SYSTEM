import { useState, useEffect } from "react";
import { results } from "./services";

export default function Results() {
    const [data, setData] = useState({});
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchResults = async () => {
            setLoading(true);
            const res = await results();
            setData(res);
            setLoading(false);
        };

        fetchResults();
        // Refresh results every 5 seconds
        const interval = setInterval(fetchResults, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="results-section">
            <h3>📊 Live Results</h3>

            {loading ? (
                <div className="no-results">Loading results...</div>
            ) : Object.keys(data).length > 0 ? (
                <div className="results-grid">
                    {Object.keys(data).map(k => (
                        <div key={k} className="result-item">
                            <span className="result-name">{k}</span>
                            <span className="result-count">{data[k]} vote{data[k] !== 1 ? 's' : ''}</span>
                        </div>
                    ))}
                </div>
            ) : (
                <div className="no-results">No votes cast yet</div>
            )}
        </div>
    );
}
