module ServerHelper
  def url_for_user
    user_page_url(:username => session[:umnauth].internet_id)
  end
end
