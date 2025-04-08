import { defineConfig, presetIcons, presetWind3, transformerVariantGroup } from 'unocss'

export default defineConfig({
	presets: [
		presetWind3(),
		presetIcons(),
	],
	transformers: [
		transformerVariantGroup(),
	],
  cli: {
    entry: {
			outFile: 'public/css/uno.css',
			patterns: [
				'public/index.html'
			]
		}
  }
})