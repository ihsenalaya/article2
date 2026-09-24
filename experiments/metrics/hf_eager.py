import torch, time
from transformers import AutoModelForCausalLM, AutoTokenizer
M="/models/Qwen2.5-7B-Instruct"
tok=AutoTokenizer.from_pretrained(M)
t0=time.time()
model=AutoModelForCausalLM.from_pretrained(M, dtype=torch.bfloat16,
        attn_implementation="eager").cuda().eval()
print(f"loaded {time.time()-t0:.0f}s, attn=eager (pure PyTorch, NO optimized kernel)")
for p in ["What is the capital of France? Answer in one word.",
          "What is 2+2? Answer with just the number."]:
    txt=tok.apply_chat_template([{"role":"user","content":p}],tokenize=False,add_generation_prompt=True)
    ids=tok(txt,return_tensors="pt").to("cuda")
    with torch.no_grad():
        o=model.generate(**ids,max_new_tokens=24,do_sample=False)
    print(f"  {p!r}\n   -> {tok.decode(o[0][ids['input_ids'].shape[1]:],skip_special_tokens=True)!r}")
