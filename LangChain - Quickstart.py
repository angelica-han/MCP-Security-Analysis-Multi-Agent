import os
from google.colab import userdata
!pip install langchain-openai

# Replace 'YOUR_OPENAI_API_KEY' with your actual OpenAI API key
os.environ["OPENAI_API_KEY"] = userdata.get('OPENAI_API_KEY')

from langchain.agents import create_agent
from langchain_openai import ChatOpenAI

import urllib.error
import urllib.request
from langchain.tools import tool
from langchain.chat_models import init_chat_model
from langgraph.checkpoint.memory import InMemorySaver

#tool
def fetch_text_from_url(url: str) -> str:
    """Fetch the document from a URL.
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; quickstart-research/1.0)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read()
    except urllib.error.URLError as e:
        return f"Fetch failed: {e}"
    text = raw.decode("utf-8", errors="replace")
    return text

tools=[fetch_text_from_url]
SYSTEM_PROMPT = """You are a literary data assistant.

## Capabilities

- `fetch_text_from_url`: loads document text from a URL into the conversation.
Do not guess line counts or positions—ground them in tool results from the saved file."""

# Initialize the ChatOpenAI model with desired parameters
llm = ChatOpenAI(
    model="gpt-4o", # Using a more recent model here, you can change it to gpt-5.4 if available
    temperature=0.5,
    timeout=300,
    max_tokens=16384 # Adjusted max_tokens to the model's supported limit
)

checkpointer = InMemorySaver()
agent = create_agent(
    model=llm,
    tools=tools,
    system_prompt=SYSTEM_PROMPT,
    checkpointer=checkpointer,
)

result = agent.invoke(
    {"messages": [{"role": "user", "content": "Fetch the content from https://example.com and summarize it"}]},
    config={"configurable": {"thread_id": "some-random-id"}}
)

checkpointer = InMemorySaver()

print(result["messages"][-1].content)
