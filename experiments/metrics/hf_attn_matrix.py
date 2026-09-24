import torch, gc
from transformers import AutoModelForCausalLM, AutoTokenizer
M="/models/Qwen2.5-7B-Instruct"
tok=AutoTokenizer.from_pretrained(M)
txt=tok.apply_chat_template([{"role":"user","content":"What is the capital of France? Answer in one word."}],
                            tokenize=False, add_generation_prompt=True)
for impl in ["eager","sdpa","flash_attention_2"]:
    try:
        m=AutoModelForCausalLM.from_pretrained(M,dtype=torch.bfloat16,attn_implementation=impl).cuda().eval()
        ids=tok(txt,return_tensors="pt").to("cuda")
        with torch.no_grad():
            o=m.generate(**ids,max_new_tokens=16,do_sample=False)
        out=tok.decode(o[0][ids['input_ids'].shape[1]:],skip_special_tokens=True)
        verdict="OK" if "paris" in out.lower() else "*** DEGENERATE ***"
        print(f"{impl:20s} {verdict:20s} -> {out!r}")
        del m, ids, o; gc.collect(); torch.cuda.empty_cache()
    except Exception as e:
        print(f"{impl:20s} UNAVAILABLE          -> {type(e).__name__}: {str(e)[:90]}")
