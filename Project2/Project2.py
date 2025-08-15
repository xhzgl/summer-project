import cv2
import numpy as np
import matplotlib.pyplot as plt
from skimage.metrics import peak_signal_noise_ratio as psnr
from skimage.metrics import structural_similarity as ssim
import os
import random


class DCTWatermark:

    def __init__(self, strength=25, block_size=8, pattern=[(4, 1), (3, 2)]):
        self.strength = strength
        self.block_size = block_size
        self.pattern = pattern

    def _get_dct_blocks(self, img):
        h, w = img.shape
        blocks = []
        h = h - h % self.block_size
        w = w - w % self.block_size

        for y in range(0, h, self.block_size):
            for x in range(0, w, self.block_size):
                block = img[y:y + self.block_size, x:x + self.block_size]
                if block.shape == (self.block_size, self.block_size):
                    dct_block = cv2.dct(np.float32(block))
                    blocks.append((y, x, dct_block))

        return blocks, h, w

    def _merge_blocks(self, blocks, img_shape):

        reconstructed = np.zeros(img_shape, dtype=np.float32)

        for y, x, dct_block in blocks:
            idct_block = cv2.idct(dct_block)
            reconstructed[y:y + self.block_size, x:x + self.block_size] = idct_block

        return reconstructed

    def embed(self, host_img, watermark):
        ycrcb = cv2.cvtColor(host_img, cv2.COLOR_BGR2YCrCb)
        y_channel = ycrcb[:, :, 0].copy()
        wm_h = y_channel.shape[0] // self.block_size
        wm_w = y_channel.shape[1] // self.block_size
        watermark = cv2.resize(watermark, (wm_w, wm_h))

        watermark_bin = (watermark > 128).astype(np.float32)
        watermark_data = watermark_bin * 2 - 1

        # 获取DCT块
        blocks, h, w = self._get_dct_blocks(y_channel)

        # 嵌入水印到DCT系数
        watermarked_blocks = []
        wm_idx = 0

        for y, x, dct_block in blocks:
            if wm_idx < watermark_data.size:
                wm_bit = watermark_data.flat[wm_idx]

                for pos in self.pattern:
                    if pos != (0, 0):
                        dct_block[pos] += self.strength * wm_bit

                wm_idx += 1

            watermarked_blocks.append((y, x, dct_block))

        watermarked_y = self._merge_blocks(watermarked_blocks, (h, w))
        watermarked_y = np.clip(watermarked_y, 0, 255).astype(np.uint8)

        ycrcb[:, :, 0] = watermarked_y
        watermarked_img = cv2.cvtColor(ycrcb, cv2.COLOR_YCrCb2BGR)

        return watermarked_img, watermarked_y

    def extract(self, watermarked_img, watermark_shape):

        ycrcb = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2YCrCb)
        y_channel = ycrcb[:, :, 0]
        blocks, _, _ = self._get_dct_blocks(y_channel)
        watermark_size = watermark_shape[0] * watermark_shape[1]
        watermark = np.zeros(watermark_size, dtype=np.float32)
        counts = np.zeros(watermark_size, dtype=np.int32)
        wm_idx = 0

        for _, _, dct_block in blocks:
            if wm_idx < watermark_size:
                wm_val = 0
                for pos in self.pattern:
                    if pos != (0, 0):
                        wm_val += dct_block[pos]

                watermark[wm_idx] += wm_val
                counts[wm_idx] += 1
                wm_idx += 1
            else:
                wm_idx = 0
                watermark[wm_idx] += wm_val
                counts[wm_idx] += 1
                wm_idx += 1

        watermark /= np.maximum(counts, 1)
        watermark_bin = (watermark > 0).astype(np.uint8) * 255
        extracted = watermark_bin.reshape(watermark_shape)

        return extracted

    def evaluate_quality(self, original, watermarked):

        psnr_value = psnr(original, watermarked)

        if len(original.shape) == 3:
            ssim_value, _ = ssim(original, watermarked, full=True, multichannel=True)
        else:
            ssim_value, _ = ssim(original, watermarked, full=True)

        return psnr_value, ssim_value


class RobustnessTester:

    def __init__(self, watermark_shape):

        self.watermark_shape = watermark_shape

    def apply_rotation(self, img, angle):

        h, w = img.shape[:2]
        center = (w // 2, h // 2)
        M = cv2.getRotationMatrix2D(center, angle, 1.0)
        return cv2.warpAffine(img, M, (w, h))

    def apply_translation(self, img, dx, dy):

        h, w = img.shape[:2]
        M = np.float32([[1, 0, dx], [0, 1, dy]])
        return cv2.warpAffine(img, M, (w, h))

    def apply_cropping(self, img, crop_percent):

        h, w = img.shape[:2]
        crop_h = int(h * crop_percent)
        crop_w = int(w * crop_percent)
        return img[crop_h:h - crop_h, crop_w:w - crop_w]

    def apply_contrast(self, img, alpha):

        return cv2.convertScaleAbs(img, alpha=alpha, beta=0)

    def apply_brightness(self, img, beta):

        return cv2.convertScaleAbs(img, alpha=1.0, beta=beta)

    def apply_gaussian_noise(self, img, mean=0, sigma=25):

        noise = np.random.normal(mean, sigma, img.shape).astype(np.uint8)
        return cv2.add(img, noise)

    def apply_jpeg_compression(self, img, quality=50):

        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
        result, encimg = cv2.imencode('.jpg', img, encode_param)
        return cv2.imdecode(encimg, cv2.IMREAD_COLOR)

    def apply_resizing(self, img, scale_factor):

        h, w = img.shape[:2]
        new_size = (int(w * scale_factor), int(h * scale_factor))
        return cv2.resize(img, new_size)

    def apply_blur(self, img, kernel_size=5):

        return cv2.GaussianBlur(img, (kernel_size, kernel_size), 0)

    def calculate_nc(self, original_wm, extracted_wm):

        extracted_resized = cv2.resize(extracted_wm,
                                       (original_wm.shape[1], original_wm.shape[0]))

        orig_bin = (original_wm > 128).astype(np.float32)
        extr_bin = (extracted_resized > 128).astype(np.float32)
        numerator = np.sum(orig_bin * extr_bin)
        denominator = np.sqrt(np.sum(orig_bin ** 2)) * np.sqrt(np.sum(extr_bin ** 2))

        return numerator / denominator if denominator != 0 else 0

    def test_robustness(self, watermarked_img, original_wm, watermark_extractor):

        results = {}

        # 定义测试用例
        test_cases = [
            ("无攻击", lambda x: x),
            ("旋转15度", lambda x: self.apply_rotation(x, 15)),
            ("平移(10%,5%)", lambda x: self.apply_translation(x, x.shape[1] // 10, x.shape[0] // 20)),
            ("裁剪25%", lambda x: self.apply_cropping(x, 0.25)),
            ("对比度增强(1.5x)", lambda x: self.apply_contrast(x, 1.5)),
            ("对比度减弱(0.7x)", lambda x: self.apply_contrast(x, 0.7)),
            ("亮度增加(30)", lambda x: self.apply_brightness(x, 30)),
            ("亮度减少(-30)", lambda x: self.apply_brightness(x, -30)),
            ("高斯噪声(σ=25)", lambda x: self.apply_gaussian_noise(x, sigma=25)),
            ("JPEG压缩(质量30)", lambda x: self.apply_jpeg_compression(x, 30)),
            ("缩放(0.8x)", lambda x: self.apply_resizing(x, 0.8)),
            ("缩放(1.2x)", lambda x: self.apply_resizing(x, 1.2)),
            ("模糊(5x5)", lambda x: self.apply_blur(x, 5)),
        ]

        for name, attack_func in test_cases:
            attacked_img = attack_func(watermarked_img.copy())
            extracted_wm = watermark_extractor.extract(attacked_img, self.watermark_shape)

            nc_value = self.calculate_nc(original_wm, extracted_wm)

            results[name] = {
                "attacked_img": attacked_img,
                "extracted_wm": extracted_wm,
                "nc": nc_value
            }

        return results


def plot_results(original_img, watermarked_img, original_wm, extracted_wm, robustness_results):

    plt.figure(figsize=(18, 12))

    plt.subplot(3, 4, 1)
    plt.imshow(cv2.cvtColor(original_img, cv2.COLOR_BGR2RGB))
    plt.title("原始图像")
    plt.axis('off')

    plt.subplot(3, 4, 2)
    plt.imshow(cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2RGB))
    plt.title("含水印图像")
    plt.axis('off')

    plt.subplot(3, 4, 3)
    plt.imshow(original_wm, cmap='gray')
    plt.title("原始水印")
    plt.axis('off')

    plt.subplot(3, 4, 4)
    plt.imshow(extracted_wm, cmap='gray')
    plt.title(f"提取的水印 (NC=1.0)")
    plt.axis('off')

    for i, (name, result) in enumerate(list(robustness_results.items())[:8]):
        plt.subplot(3, 4, i + 5)

        if name == "无攻击":
            plt.imshow(cv2.cvtColor(result["attacked_img"], cv2.COLOR_BGR2RGB))
        else:
            plt.imshow(cv2.cvtColor(result["attacked_img"], cv2.COLOR_BGR2RGB))

        plt.title(f"{name}\nNC={result['nc']:.4f}")
        plt.axis('off')

    plt.tight_layout()
    plt.savefig('watermark_results.jpg')
    plt.show()

    plt.figure(figsize=(15, 8))
    plt.subplot(2, 6, 1)
    plt.imshow(original_wm, cmap='gray')
    plt.title("原始水印")
    plt.axis('off')

    plt.subplot(2, 6, 2)
    plt.imshow(extracted_wm, cmap='gray')
    plt.title("正常提取\nNC=1.0")
    plt.axis('off')

    test_cases = ["旋转15度", "平移(10%,5%)", "裁剪25%", "对比度增强(1.5x)",
                  "高斯噪声(σ=25)", "JPEG压缩(质量30)", "缩放(0.8x)", "模糊(5x5)"]

    for i, name in enumerate(test_cases[:8]):
        if name in robustness_results:
            result = robustness_results[name]
            plt.subplot(2, 6, i + 3)
            plt.imshow(result["extracted_wm"], cmap='gray')
            plt.title(f"{name}\nNC={result['nc']:.4f}")
            plt.axis('off')

    plt.tight_layout()
    plt.savefig('extracted_watermarks.jpg')
    plt.show()


def main():

    os.makedirs("results", exist_ok=True)
    host_img = cv2.imread('host.jpg')
    watermark = cv2.imread('watermark.png', cv2.IMREAD_GRAYSCALE)

    if host_img is None:
        raise FileNotFoundError("准备 'host.jpg' 文件")
    if watermark is None:
        raise FileNotFoundError("准备 'watermark.png' 文件")

    watermarker = DCTWatermark(strength=30, block_size=8, pattern=[(4, 1), (3, 2), (2, 3)])
    watermarked_img, watermarked_y = watermarker.embed(host_img, watermark)
    cv2.imwrite('results/watermarked.jpg', watermarked_img)
    cv2.imwrite('results/watermarked_y.jpg', watermarked_y)

    extracted_wm = watermarker.extract(watermarked_img, watermark.shape)
    cv2.imwrite('results/extracted_wm.png', extracted_wm)

    psnr_value, ssim_value = watermarker.evaluate_quality(host_img, watermarked_img)
    print(f"图像质量评估 - PSNR: {psnr_value:.2f} dB, SSIM: {ssim_value:.4f}")

    tester = RobustnessTester(watermark.shape)
    robustness_results = tester.test_robustness(watermarked_img, watermark, watermarker)

    for name, result in robustness_results.items():
        cv2.imwrite(f'results/{name}_attacked.jpg', result["attacked_img"])
        cv2.imwrite(f'results/{name}_extracted.png', result["extracted_wm"])

    print("\n鲁棒性测试结果 ():")
    for name, result in robustness_results.items():
        print(f"{name}: NC = {result['nc']:.4f}")

    plot_results(host_img, watermarked_img, watermark, extracted_wm, robustness_results)


if __name__ == "__main__":
    main()