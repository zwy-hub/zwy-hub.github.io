### 本地启动
```shell
bundle exec jekyll s
# 启动时预览草稿
bundle exec jekyll s --drafts
```
### 注意
- `jekyll s` 可能会启动失败，会遇到下面的错误
- You have already activated google-protobuf 4.27.0, but your Gemfile requires google-protobuf 3.25.3. Prepending `bundle exec` to your command may solve this.
这个表示当前google-protobuf已经激活的版本是4.27.0，但是项目的Gemfile使用的版本是3.25.3，要想成功启动，需要在前面添加上bundle exec，也就是bundle exec jekyll s来启动，它会根据Gemfile.lock创建一个隔离环境，确保使用正确的gem版本。
- Could not find gem 'rake (>= 12.0, < 13.0)' in locally installed gems. (Bundler::GemNotFound)
这个表示本地已经下载gem中没有找到版本为>= 12.0, < 13.0的rake依赖，可能下载了其他版本，不适配当前项目，需要先切换到项目路径下，执行命令bundle install，它会根据当前项目的Gemfile.lock，下载对应的依赖。

## 文件目录
- _data 存放数据，文章可以通过site.data访问，如default.yml中配置title信息，可以通过site.data.default[title]获取
  - default.yml
- _drafts 存放草稿，在启动命令后添加配置 `--drafts` 可以预览草稿
- _includes 组件、全局数据，以便在文章中使用
- _layouts 布局内容，包裹在文章外面
- _posts 存放文章，命令规则必须是 `年-月-日-标题.MARKUP` [链接](https://jekyllcn.com/docs/posts/)
- _sass css样式文件
- _site 启动后编译生成的文件
- .jekyll-cache
- assets 静态资源
- _config.yml 全局配置文件