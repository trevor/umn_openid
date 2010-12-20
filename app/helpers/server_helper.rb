module ServerHelper
  def url_for_user(x = session[:umnauth].internet_id)
    user_page_url(:username => x)
  end
end
