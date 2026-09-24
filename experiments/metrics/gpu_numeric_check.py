import torch
print("torch", torch.__version__, "cuda", torch.version.cuda, "dev", torch.cuda.get_device_name(0))
torch.manual_seed(0)

# 1) Host->Device->Host roundtrip integrity (tests CC memory/DMA path)
x = torch.randn(1_000_000)
back = x.cuda().cpu()
print("1) H2D/D2H roundtrip exact:", torch.equal(x, back), "maxdiff", (x-back).abs().max().item())

# 2) fp32 matmul GPU vs CPU
a = torch.randn(512, 512); b = torch.randn(512, 512)
ref = a @ b
got = (a.cuda() @ b.cuda()).cpu()
print("2) fp32 matmul maxdiff:", (ref-got).abs().max().item(), "relerr", ((ref-got).abs().max()/ref.abs().max()).item())

# 3) bf16 matmul (what vLLM actually uses)
ab = a.bfloat16(); bb = b.bfloat16()
refb = (ab.float() @ bb.float())
gotb = (ab.cuda() @ bb.cuda()).float().cpu()
print("3) bf16 matmul relerr:", ((refb-gotb).abs().max()/refb.abs().max()).item())

# 4) elementwise + reduction sanity
v = torch.ones(1024, device='cuda')
print("4) sum(ones*1024) =", v.sum().item(), "(expect 1024.0)")

# 5) read back actual model weights from disk and check on GPU
from safetensors import safe_open
import glob
f = sorted(glob.glob("/models/Qwen2.5-7B-Instruct/*.safetensors"))[0]
with safe_open(f, framework="pt") as sf:
    k = next(iter(sf.keys()))
    w = sf.get_tensor(k)
print("5) weight", k, "dtype", w.dtype, "shape", tuple(w.shape))
print("   cpu  mean/std/absmax:", w.float().mean().item(), w.float().std().item(), w.float().abs().max().item())
wg = w.cuda()
print("   gpu  mean/std/absmax:", wg.float().mean().item(), wg.float().std().item(), wg.float().abs().max().item())
print("   weights survive H2D exact:", torch.equal(w, wg.cpu()))
