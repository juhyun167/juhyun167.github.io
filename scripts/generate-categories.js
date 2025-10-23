/* global hexo */

hexo.extend.generator.register('category-data', function(locals) {
  const categories = [];

  // Get all parent categories (no parent)
  const parentCategories = locals.categories.filter(cat => !cat.parent).sort('name');

  parentCategories.forEach(category => {
    const categoryData = {
      name: category.name,
      href: hexo.config.root + category.path,
      count: category.length
    };

    // Find children for this parent
    const children = locals.categories.filter(cat => cat.parent === category._id);

    if (children.length > 0) {
      categoryData.child_category_list = children.map(child => ({
        name: child.name,
        href: hexo.config.root + child.path,
        count: child.length
      }));
    }

    categories.push(categoryData);
  });

  return {
    path: 'data/categories.json',
    data: JSON.stringify(categories)
  };
});
