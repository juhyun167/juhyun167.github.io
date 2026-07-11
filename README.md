# Publishing articles

Install dependencies once:

```bash
npm install
```

Create a new article:

```bash
npx hexo new post "article-title"
```

Edit `source/_posts/article-title.md`, then preview it locally:

```bash
npm run server
```

Before publishing, verify the production build:

```bash
npm run clean
npm run build
```

Commit and publish:

```bash
git add .
git commit -m "post: add article-title"
git push
```

Pushing to `main` automatically publishes the site through GitHub Actions.
