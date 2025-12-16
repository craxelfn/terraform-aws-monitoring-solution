exports.handler = async (event) => {
    console.log("Received event:", JSON.stringify(event, null, 2));

    const headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "OPTIONS,POST"
    };

    try {
        const body = JSON.parse(event.body || "{}");

        if (body.action === 'error') {
            console.error("CRITICAL: Simulating a failure for Observability!");
            throw new Error("Intentional 500 Error for Observability Testing");
        }

        console.log("Processing successful request...");
        
        return {
            statusCode: 200,
            headers: headers,
            body: JSON.stringify({ 
                message: "Success! The Node.js backend is healthy.",
                input: body.action 
            })
        };

    } catch (error) {
        console.error("Exception caught:", error);
        
        return {
            statusCode: 500,
            headers: headers,
            body: JSON.stringify({ error: error.message })
        };
    }
};